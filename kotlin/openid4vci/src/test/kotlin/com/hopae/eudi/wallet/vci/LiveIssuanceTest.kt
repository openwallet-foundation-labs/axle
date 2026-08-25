package com.hopae.eudi.wallet.vci

import com.hopae.eudi.wallet.cbor.cose.Der
import com.hopae.eudi.wallet.cbor.cose.EcCurve
import com.hopae.eudi.wallet.cbor.cose.EcPublicKey
import com.hopae.eudi.wallet.sdjwt.Base64Url
import com.hopae.eudi.wallet.sdjwt.JsonValue
import com.hopae.eudi.wallet.sdjwt.JwkEc
import com.hopae.eudi.wallet.sdjwt.Jws
import com.hopae.eudi.wallet.sdjwt.JwsSigner
import com.hopae.eudi.wallet.sdjwt.JwtTimeValidator
import com.hopae.eudi.wallet.sdjwt.JwtVcMetadataKeyResolver
import com.hopae.eudi.wallet.sdjwt.SdJwt
import com.hopae.eudi.wallet.sdjwt.SdJwtVcVerifier
import com.hopae.eudi.wallet.spi.Rng
import com.hopae.eudi.wallet.spi.SigningAlgorithm
import kotlinx.coroutines.runBlocking
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.junit.jupiter.api.Assumptions.assumeTrue
import java.io.File
import java.math.BigInteger
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.SecureRandom
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.PKCS8EncodedKeySpec
import java.time.Instant
import java.util.Base64
import java.util.Date
import kotlin.test.Test

/**
 * Manual two-step live PID issuance from issuer.eudiw.dev.
 *
 *   Step 1 (get the URL):  EUDI_LIVE=prepare ./gradlew :openid4vci:test --tests '*LiveIssuanceTest*'
 *   -> open the printed URL in a browser, authenticate, copy the `code` from the redirect.
 *   Step 2 (complete):     EUDI_LIVE=finish EUDI_CODE=<code> ./gradlew ... (same filter)
 *
 * State + holder keys are persisted between the two runs. Uses the authorization code grant.
 */
class LiveIssuanceTest {

    private val issuer = "https://issuer.eudiw.dev"
    // Credential to request in the authorization-code flow; override for mdoc (eu.europa.ec.eudi.pid_mdoc).
    private val configId = System.getenv("EUDI_CONFIG_ID") ?: "eu.europa.ec.eudi.pid_vc_sd_jwt"
    private val redirectUri = "https://example.org/cb"
    private val stateFile = File(System.getProperty("java.io.tmpdir"), "eudi-live-issuance.json")

    private fun secureRng(): Rng {
        val sr = SecureRandom()
        return Rng { size -> ByteArray(size).also(sr::nextBytes) }
    }

    private fun client() = Openid4VciClient(
        JdkHttpTransport(), secureRng(),
        clock = { System.currentTimeMillis() / 1000 },
        clientId = "wallet-dev",
    )

    /**
     * A Key Attestation this harness signs itself (OpenID4VCI Appendix D), over exactly [attestedKeys] and
     * bound to the c_nonce.
     *
     * Every issuer.eudiw.dev config declares `key_attestations_required`, so the client will not send a
     * proof without an attestation source — HAIP §4.5.1 makes that declaration binding on the Wallet. The
     * issuer itself does not enforce it (a bare `jwt` proof is issued a PID just the same, and so is an
     * attestation asserting a level below the one it asks for), so nothing here has to be real. It only has
     * to be well-formed: an attestation with no `x5c` at all draws a 500 from the issuer rather than a
     * clean rejection, so the JWT carries a self-signed certificate for the key that signed it.
     *
     * Deliberately self-contained. The demo wallet gets this from its Wallet Provider, and the harness
     * could call the same endpoint, but then an outage there would fail a run that is meant to be testing
     * the issuer.
     */
    private fun selfSignedKeyAttestation(attestedKeys: List<EcPublicKey>) = KeyAttestationSource { cNonce ->
        val kp = KeyPairGenerator.getInstance("EC")
            .apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
        val nowMs = System.currentTimeMillis()
        val name = X500Name("CN=Axle live-interop harness")
        val cert = JcaX509CertificateConverter().getCertificate(
            JcaX509v3CertificateBuilder(
                name, BigInteger.valueOf(nowMs), Date(nowMs - 60_000), Date(nowMs + 3_600_000), name, kp.public,
            ).build(JcaContentSignerBuilder("SHA256withECDSA").build(kp.private))
        )
        val signer = object : JwsSigner {
            override val algorithm = SigningAlgorithm.ES256
            override suspend fun sign(signingInput: ByteArray): ByteArray =
                Signature.getInstance("SHA256withECDSA").run {
                    initSign(kp.private)
                    update(signingInput)
                    Der.derSignatureToRaw(sign(), 32)
                }
        }
        val header = JsonValue.Obj(
            listOf(
                "typ" to JsonValue.Str("keyattestation+jwt"),
                "alg" to JsonValue.Str("ES256"),
                "x5c" to JsonValue.Arr(listOf(JsonValue.Str(Base64.getEncoder().encodeToString(cert.encoded)))),
            )
        )
        val seconds = nowMs / 1000
        val claims = JsonValue.Obj(
            buildList {
                add("iss" to JsonValue.Str("https://example.org/live-interop"))
                add("iat" to JsonValue.NumInt(seconds))
                add("exp" to JsonValue.NumInt(seconds + 300))
                cNonce?.let { add("nonce" to JsonValue.Str(it)) }
                add("attested_keys" to JsonValue.Arr(attestedKeys.map { JwkEc.toJson(it) }))
                add("key_storage" to JsonValue.Arr(listOf(JsonValue.Str("iso_18045_moderate"))))
                add("user_authentication" to JsonValue.Arr(listOf(JsonValue.Str("iso_18045_moderate"))))
            }
        )
        Jws.sign(header, claims.serialize().encodeToByteArray(), signer).compact()
    }

    @Test
    fun step1_prepare() = runBlocking {
        assumeTrue(System.getenv("EUDI_LIVE") == "prepare", "run with EUDI_LIVE=prepare")

        val proof = LocalEcKey.generate()
        val dpop = LocalEcKey.generate()
        val client = client()

        // If a credential offer (deep link) is provided, use its issuer/config/issuer_state.
        val offerInput = System.getenv("EUDI_OFFER")
        val offer = offerInput?.let { client.resolveCredentialOffer(it) }
        val useIssuer = offer?.credentialIssuer ?: issuer
        val useConfig = offer?.credentialConfigurationIds?.first() ?: configId
        val issuerState = offer?.authorizationCodeIssuerState
        if (offer != null) println("resolved offer: issuer=$useIssuer config=$useConfig issuer_state=$issuerState")

        val prepared = client.prepareAuthorizationCodeIssuance(
            credentialIssuer = useIssuer,
            configurationId = useConfig,
            redirectUri = redirectUri,
            issuerState = issuerState,
        )

        val state = JsonValue.Obj(
            listOf(
                "credentialIssuer" to JsonValue.Str(useIssuer),
                "configurationId" to JsonValue.Str(useConfig),
                "codeVerifier" to JsonValue.Str(prepared.pkce.codeVerifier),
                "redirectUri" to JsonValue.Str(redirectUri),
                "proof" to proof.toJson(),
                "dpop" to dpop.toJson(),
            )
        )
        stateFile.writeText(state.serialize())

        println("\n================ OPEN THIS URL IN A BROWSER ================\n")
        println(prepared.authorizationUrl)
        println("\nAfter authenticating, you'll be redirected to:")
        println("  $redirectUri?code=<CODE>&state=...")
        println("Copy the <CODE> value, then run step 2 with EUDI_LIVE=finish EUDI_CODE=<CODE>.")
        println("(state saved to ${stateFile.absolutePath})\n")
    }

    /**
     * Pre-authorized code flow — fully headless, no authorization endpoint or browser.
     * Reads a pre-auth offer (EUDI_OFFER) + transaction code (EUDI_TXCODE) captured from the
     * portal and redeems them directly at the token endpoint.
     */
    @Test
    fun preAuthIssue() = runBlocking {
        assumeTrue(System.getenv("EUDI_LIVE") == "preauth", "run with EUDI_LIVE=preauth")
        val offerInput = System.getenv("EUDI_OFFER") ?: error("set EUDI_OFFER=<pre-auth offer link>")
        val txCode = System.getenv("EUDI_TXCODE") ?: error("set EUDI_TXCODE=<transaction code>")
        val transport = JdkHttpTransport()

        val proof = LocalEcKey.generate()
        val dpop = LocalEcKey.generate()
        val keys = IssuanceKeys(
            proof.signer(), proof.publicKey, dpop.signer(), dpop.publicKey,
            keyAttestation = selfSignedKeyAttestation(listOf(proof.publicKey)),
        )

        // EUDI_ENCRYPT=1 exercises OpenID4VCI §8.2/§10: the Credential Request goes out as a JWE and the
        // Credential Response comes back as application/jwt. issuer.eudiw.dev advertises both.
        val encryption = if (System.getenv("EUDI_ENCRYPT") == "1") CredentialEncryption.Preferred else CredentialEncryption.WhenRequired
        val client = Openid4VciClient(
            transport, secureRng(), clock = { System.currentTimeMillis() / 1000 }, clientId = "wallet-dev",
            credentialEncryption = encryption,
        )
        val offer = client.resolveCredentialOffer(offerInput)
        println("pre-auth offer: config=${offer.credentialConfigurationIds.first()} txCodeRequired=${offer.txCode != null} encryption=$encryption")

        val response = client.issueWithPreAuthorizedCode(
            offer = offer,
            configurationId = offer.credentialConfigurationIds.first(),
            keys = keys,
            txCode = txCode,
        )
        println("credentials received: ${response.credentials.size}")
        val credential = response.credentials.first().credential
        File(System.getProperty("java.io.tmpdir"), "eudi-credential.txt").writeText(credential)
        // Persist the holder (proof) key — its public key is the credential's cnf, so it can
        // later sign the KB-JWT for an OpenID4VP presentation.
        File(System.getProperty("java.io.tmpdir"), "eudi-holder-key.json").writeText(proof.toJson().serialize())
        println("credential + holder key saved — verify with VerifySavedPidTest, present with VpPresentTest")
    }

    @Test
    fun step2_finish() = runBlocking {
        assumeTrue(System.getenv("EUDI_LIVE") == "finish", "run with EUDI_LIVE=finish")
        // Prefer a redirect-URL file (no manual transcription): write the full redirect to
        // /tmp/eudi-redirect.txt, we extract and URL-decode the `code` ourselves.
        val redirectFile = File(System.getProperty("java.io.tmpdir"), "eudi-redirect.txt")
        val code = when {
            redirectFile.exists() -> {
                val url = redirectFile.readText().trim()
                val raw = url.substringAfter("code=").substringBefore('&')
                java.net.URLDecoder.decode(raw, "UTF-8")
            }
            else -> System.getenv("EUDI_CODE") ?: error("write redirect to ${redirectFile.absolutePath} or set EUDI_CODE")
        }
        println("using authorization code (len=${code.length})")
        val transport = JdkHttpTransport()

        val state = JsonValue.parse(stateFile.readText()) as JsonValue.Obj
        val proof = LocalEcKey.fromJson(state["proof"] as JsonValue.Obj)
        val dpop = LocalEcKey.fromJson(state["dpop"] as JsonValue.Obj)
        val codeVerifier = (state["codeVerifier"] as JsonValue.Str).value
        val redirect = (state["redirectUri"] as JsonValue.Str).value
        val useIssuer = (state["credentialIssuer"] as? JsonValue.Str)?.value ?: issuer
        val useConfig = (state["configurationId"] as? JsonValue.Str)?.value ?: configId

        val keys = IssuanceKeys(
            proof.signer(), proof.publicKey, dpop.signer(), dpop.publicKey,
            keyAttestation = selfSignedKeyAttestation(listOf(proof.publicKey)),
        )

        val client = Openid4VciClient(
            transport, secureRng(), clock = { System.currentTimeMillis() / 1000 }, clientId = "wallet-dev",
        )
        val response = client.exchangeAuthorizationCode(
            credentialIssuer = useIssuer,
            configurationId = useConfig,
            authorizationCode = code,
            redirectUri = redirect,
            codeVerifier = codeVerifier,
            keys = keys,
        )

        println("\n================ LIVE ISSUANCE RESULT ================")
        println("credentials received: ${response.credentials.size}")
        val credential = response.credentials.first().credential

        // Save the real credential FIRST — never lose it to a later verification error.
        val credFile = File(System.getProperty("java.io.tmpdir"), "eudi-credential.txt")
        credFile.writeText(credential)
        println("credential saved to ${credFile.absolutePath} (${credential.length} chars)")

        // mdoc credentials are base64url CBOR, not SD-JWT — verify those with verifyRealMdocWithChain.
        if (configId.contains("mdoc")) {
            println("mso_mdoc credential saved — verify with LiveTrustE2eTest.verifyRealMdocWithChain")
            println("=====================================================\n")
            return@runBlocking
        }

        // Show the issuer JWS header + payload (unverified) for diagnostics.
        val parsed = SdJwt.parse(credential)
        val jws = com.hopae.eudi.wallet.sdjwt.Jws.parse(parsed.jwt)
        println("JWS header: ${jws.header.serialize()}")
        val payload = JsonValue.parse(jws.payloadBytes.decodeToString()) as JsonValue.Obj
        println("payload keys: ${payload.entries.map { it.first }}")
        println("disclosures: ${parsed.disclosures.size}")

        try {
            val verified = SdJwtVcVerifier(
                JwtVcMetadataKeyResolver(transport),
                JwtTimeValidator(now = { Instant.now() }),
            ).verify(parsed)
            println("\n*** VERIFIED SD-JWT VC ***")
            println("vct:    ${verified.vct}")
            println("issuer: ${verified.issuer}")
            println("claims:")
            verified.claims.entries.forEach { (k, v) -> println("  $k = ${v.serialize()}") }
            println("holder-bound: ${verified.holderKey != null}")
        } catch (e: Exception) {
            println("\n[verification failed: ${e.message}] — credential is saved; diagnosing resolver path")
            val x5c = jws.x5c
            println("issuer JWS has x5c: ${x5c != null} (${x5c?.size ?: 0} certs)")
        }
        println("=====================================================\n")
    }
}

/** Local JCA-backed EC key for the manual live test (persists across the two runs). */
private class LocalEcKey(val privateKey: PrivateKey, val publicKey: EcPublicKey, val pkcs8: ByteArray) {

    fun signer(): JwsSigner = object : JwsSigner {
        override val algorithm = SigningAlgorithm.ES256
        override suspend fun sign(signingInput: ByteArray): ByteArray =
            Signature.getInstance("SHA256withECDSA").run {
                initSign(privateKey)
                update(signingInput)
                Der.derSignatureToRaw(sign(), 32)
            }
    }

    fun toJson(): JsonValue = JsonValue.Obj(
        listOf(
            "pkcs8" to JsonValue.Str(Base64.getEncoder().encodeToString(pkcs8)),
            "x" to JsonValue.Str(Base64Url.encode(publicKey.x)),
            "y" to JsonValue.Str(Base64Url.encode(publicKey.y)),
        )
    )

    companion object {
        fun generate(): LocalEcKey {
            val kp = KeyPairGenerator.getInstance("EC")
                .apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
            val pub = kp.public as ECPublicKey
            fun fixed(b: BigInteger): ByteArray {
                val s = b.toByteArray().dropWhile { it == 0.toByte() }.toByteArray()
                return ByteArray(32 - s.size) + s
            }
            val ec = EcPublicKey(EcCurve.P256, fixed(pub.w.affineX), fixed(pub.w.affineY))
            return LocalEcKey(kp.private, ec, kp.private.encoded)
        }

        fun fromJson(o: JsonValue.Obj): LocalEcKey {
            val pkcs8 = Base64.getDecoder().decode((o["pkcs8"] as JsonValue.Str).value)
            val priv = KeyFactory.getInstance("EC").generatePrivate(PKCS8EncodedKeySpec(pkcs8))
            val x = Base64Url.decode((o["x"] as JsonValue.Str).value)
            val y = Base64Url.decode((o["y"] as JsonValue.Str).value)
            return LocalEcKey(priv, EcPublicKey(EcCurve.P256, x, y), pkcs8)
        }
    }
}
