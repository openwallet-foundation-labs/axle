package com.hopae.eudi.wallet.vci

import com.hopae.eudi.wallet.cbor.cose.EcCurve
import com.hopae.eudi.wallet.cbor.cose.EcPublicKey
import com.hopae.eudi.wallet.sdjwt.IssuerKeyResolver
import com.hopae.eudi.wallet.sdjwt.IssuerSigningKey
import com.hopae.eudi.wallet.sdjwt.JsonValue
import com.hopae.eudi.wallet.sdjwt.Jws
import com.hopae.eudi.wallet.sdjwt.JwtTimeValidator
import com.hopae.eudi.wallet.sdjwt.SdJwt
import com.hopae.eudi.wallet.sdjwt.SdJwtVcException
import com.hopae.eudi.wallet.sdjwt.SdJwtVcVerifier
import com.hopae.eudi.wallet.spi.SigningAlgorithm
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Assumptions.assumeTrue
import java.io.ByteArrayInputStream
import java.io.File
import java.math.BigInteger
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.interfaces.ECPublicKey
import java.time.Instant
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * Verifies the real PID SD-JWT VC captured from issuer.eudiw.dev (offline, no auth code).
 * The live issuer signs with an x5c certificate chain, so this uses an x5c-based issuer key
 * resolver (leaf public key extraction). Chain validation against IACA trust anchors is the
 * trust module's job (M3) — here we prove the issuer signature verifies with the leaf key.
 */
class VerifySavedPidTest {

    @Test
    fun verifyRealPidFromDisk() = runBlocking {
        val file = File(System.getProperty("java.io.tmpdir"), "eudi-credential.txt")
        assumeTrue(file.exists(), "no captured credential at ${file.absolutePath} (run a live issuance first)")

        val sdJwt = SdJwt.parse(file.readText())
        val leaf = leafCertificate(sdJwt)
        println("issuer cert subject: ${leaf.subjectX500Principal}")
        println("issuer cert SAN/issuer: ${leaf.issuerX500Principal}")
        println("cert valid: ${leaf.notBefore} .. ${leaf.notAfter}")

        val verified = SdJwtVcVerifier(
            issuerKeyResolver = X5cLeafKeyResolver,
            timeValidator = JwtTimeValidator(now = { Instant.now() }),
        ).verify(sdJwt)

        println("\n*** VERIFIED REAL EUDI PID ***")
        println("vct:    ${verified.vct}")
        println("issuer: ${verified.issuer}")
        println("holder-bound (cnf): ${verified.holderKey != null}")
        println("status present: ${verified.status != null}")
        println("disclosed claims:")
        verified.claims.entries.forEach { (k, v) -> println("  $k = ${v.serialize()}") }

        assertEquals("urn:eudi:pid:1", verified.vct)
        assertTrue(verified.issuer.contains("issuer.eudiw.dev"), "issuer: ${verified.issuer}")
        assertTrue(verified.holderKey != null, "PID must be holder-bound via cnf")
        assertTrue(
            verified.claims["family_name"] != null && verified.claims["given_name"] != null,
            "PID must expose the disclosed name claims",
        )
    }

    private fun leafCertificate(sdJwt: SdJwt): X509Certificate {
        val x5c = Jws.parse(sdJwt.jwt).x5c ?: throw SdJwtVcException("no x5c in issuer JWS")
        return CertificateFactory.getInstance("X.509")
            .generateCertificate(ByteArrayInputStream(x5c.first())) as X509Certificate
    }
}

/**
 * Extracts the issuer signing key from the leaf certificate in the JWS `x5c` header.
 * NOTE: does not validate the chain — that is the trust module's responsibility (M3).
 */
object X5cLeafKeyResolver : IssuerKeyResolver {
    override suspend fun resolve(iss: String, header: JsonValue.Obj): IssuerSigningKey {
        val x5c = header["x5c"] as? JsonValue.Arr ?: throw SdJwtVcException("no x5c header")
        val leafB64 = (x5c.items.first() as? JsonValue.Str)?.value ?: throw SdJwtVcException("bad x5c entry")
        val der = java.util.Base64.getDecoder().decode(leafB64)
        val cert = CertificateFactory.getInstance("X.509")
            .generateCertificate(ByteArrayInputStream(der)) as X509Certificate
        val pub = cert.publicKey as? ECPublicKey ?: throw SdJwtVcException("issuer key is not EC")

        val fieldSize = (pub.params.curve.field.fieldSize + 7) / 8
        val curve = when (fieldSize) {
            32 -> EcCurve.P256
            48 -> EcCurve.P384
            66 -> EcCurve.P521
            else -> throw SdJwtVcException("unsupported curve size $fieldSize")
        }
        fun fixed(b: BigInteger): ByteArray {
            val s = b.toByteArray().dropWhile { it == 0.toByte() }.toByteArray()
            return ByteArray(fieldSize - s.size) + s
        }
        val ec = EcPublicKey(curve, fixed(pub.w.affineX), fixed(pub.w.affineY))
        val alg = when (curve) {
            EcCurve.P256 -> SigningAlgorithm.ES256
            EcCurve.P384 -> SigningAlgorithm.ES384
            EcCurve.P521 -> SigningAlgorithm.ES512
        }
        return IssuerSigningKey(ec, alg)
    }
}
