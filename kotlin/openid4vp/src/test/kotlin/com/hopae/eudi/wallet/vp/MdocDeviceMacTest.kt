package com.hopae.eudi.wallet.vp

import com.hopae.eudi.wallet.cbor.Cbor
import com.hopae.eudi.wallet.cbor.CborDecoder
import com.hopae.eudi.wallet.cbor.CborEncoder
import com.hopae.eudi.wallet.cbor.cose.CoseMac0
import com.hopae.eudi.wallet.cbor.cose.EcCurve
import com.hopae.eudi.wallet.cbor.cose.EcPublicKey
import com.hopae.eudi.wallet.mdoc.IssuerSigned
import com.hopae.eudi.wallet.mdoc.MdocDeviceAuth
import com.hopae.eudi.wallet.mdoc.MdocDeviceAuthMode
import com.hopae.eudi.wallet.mdoc.MdocKeyAgreement
import com.hopae.eudi.wallet.mdoc.MdocTestIssuer
import com.hopae.eudi.wallet.sdjwt.Base64Url
import com.hopae.eudi.wallet.sdjwt.JsonValue
import com.hopae.eudi.wallet.sdjwt.JweRecipientKey
import com.hopae.eudi.wallet.spi.KeySpec
import com.hopae.eudi.wallet.spi.SecureAreaCoseSigner
import com.hopae.eudi.wallet.spi.SigningAlgorithm
import com.hopae.eudi.wallet.testkit.SoftwareSecureArea
import kotlinx.coroutines.runBlocking
import java.time.Instant
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * OpenID4VP mdoc `deviceMac` (ISO 18013-7 B.4.5 / OpenID4VP §B.2.2). The wallet MACs the DeviceResponse
 * when the verifier requests it via `deviceauth_alg_values`, keyed by ECDH between the mdoc `DeviceKey`
 * and the verifier's `EReaderKey` (its response-encryption key) — otherwise it signs.
 */
class MdocDeviceMacTest {

    private val docType = "org.iso.18013.5.1.mDL"
    private val namespace = "org.iso.18013.5.1"
    private val origin = "https://verifier.example"
    private val MAC_P256 = -65537L
    private val ES256 = -7L

    private class Fixture(
        val area: SoftwareSecureArea,
        val issuerSigned: IssuerSigned,
        val deviceKeyHandle: com.hopae.eudi.wallet.spi.KeyHandle,
        val deviceKey: EcPublicKey,
    ) {
        fun held(pref: MdocDeviceAuthMode, keyAgree: Boolean = true) = HeldMdoc(
            "mdl-1", issuerSigned, SecureAreaCoseSigner(area, deviceKeyHandle, SigningAlgorithm.ES256),
            deviceKeyAgreement = if (keyAgree) MdocKeyAgreement { peer -> area.keyAgreement(deviceKeyHandle, peer) } else null,
            deviceAuth = pref,
        )
    }

    private fun fixture(): Fixture = runBlocking {
        val area = SoftwareSecureArea()
        val issuerKey = area.createKey(KeySpec(secureArea = area.id, algorithm = SigningAlgorithm.ES256))
        val deviceKey = area.createKey(KeySpec(secureArea = area.id, algorithm = SigningAlgorithm.ES256))
        val bytes = MdocTestIssuer.issue(
            area = area, issuerKey = issuerKey, deviceKey = deviceKey.publicKey, docType = docType, namespace = namespace,
            elements = listOf("family_name" to Cbor.Text("Han"), "given_name" to Cbor.Text("Jongho")),
            x5chain = listOf(byteArrayOf(0x30, 0x01)),
            signed = Instant.parse("2026-01-01T00:00:00Z"), validFrom = Instant.parse("2026-01-01T00:00:00Z"), validUntil = Instant.parse("2027-01-01T00:00:00Z"),
        )
        Fixture(area, IssuerSigned.decode(bytes), deviceKey.handle, deviceKey.publicKey)
    }

    private fun ctx(fx: Fixture, encKey: EcPublicKey?, algs: List<Long>?, thumbprint: ByteArray? = null) = PresentationContext(
        disclosedPaths = listOf(listOf(namespace, "family_name"), listOf(namespace, "given_name")),
        clientId = "verifier", nonce = "vp-nonce", responseUri = "https://verifier.example/cb",
        issuedAt = 1_700_000_000, transactionData = null, verifierJwkThumbprint = thumbprint,
        verifierEncryptionKey = encKey, deviceAuthAlgValues = algs,
    )

    /** A standalone verifier encryption public key (the EReaderKey), on P-256. */
    private fun encKey(): EcPublicKey = runBlocking {
        val a = SoftwareSecureArea()
        a.createKey(KeySpec(secureArea = a.id, algorithm = SigningAlgorithm.ES256)).publicKey
    }

    private fun map(c: Cbor, key: String): Cbor? =
        (c as Cbor.CborMap).entries.firstOrNull { (k, _) -> (k as? Cbor.Text)?.value == key }?.second

    /** Reader-side check: recompute the EMacKey (ECDH is symmetric) and verify the deviceMac binds the transcript. */
    private fun assertDeviceMacVerifies(fx: Fixture, presentation: String, encKey: EcPublicKey, thumbprint: ByteArray?) = runBlocking {
        val deviceResponse = CborDecoder.decode(Base64Url.decode(presentation))
        val document = (map(deviceResponse, "documents") as Cbor.Array).items.single()
        val deviceAuth = map(map(document, "deviceSigned")!!, "deviceAuth")!!
        assertNull(map(deviceAuth, "deviceSignature"), "must not sign when the verifier requested deviceMac")
        val deviceMac = CoseMac0.fromCbor(map(deviceAuth, "deviceMac") ?: error("no deviceMac"))

        val sessionTranscript = Oid4vpSessionTranscript.build("verifier", "https://verifier.example/cb", "vp-nonce", thumbprint)
        val deviceNsBytes = Cbor.Tagged(24u, Cbor.Bytes(CborEncoder.encode(Cbor.CborMap(emptyList()))))
        val da = Cbor.Array(listOf(Cbor.Text("DeviceAuthentication"), sessionTranscript, Cbor.Text(docType), deviceNsBytes))
        val deviceAuthBytes = CborEncoder.encode(Cbor.Tagged(24u, Cbor.Bytes(CborEncoder.encode(da))))
        val zab = fx.area.keyAgreement(fx.deviceKeyHandle, encKey)
        val emacKey = MdocDeviceAuth.emacKey(zab, sessionTranscript)
        assertTrue(deviceMac.verify(emacKey, detachedPayload = deviceAuthBytes), "deviceMac must bind DeviceAuthentication")
    }

    @Test
    fun producesDeviceMacWhenVerifierRequestsIt() = runBlocking {
        val fx = fixture()
        val enc = encKey()
        val presentation = fx.held(MdocDeviceAuthMode.Mac).present(ctx(fx, enc, listOf(MAC_P256, ES256)))
        assertDeviceMacVerifies(fx, presentation, enc, null)
    }

    @Test
    fun forcesDeviceMacWhenVerifierAcceptsOnlyMac() = runBlocking {
        // Even with the default Signature preference, an only-MAC verifier is satisfied with a deviceMac.
        val fx = fixture()
        val enc = encKey()
        val presentation = fx.held(MdocDeviceAuthMode.Signature).present(ctx(fx, enc, listOf(MAC_P256)))
        assertDeviceMacVerifies(fx, presentation, enc, null)
    }

    @Test
    fun defaultsToSignatureWhenBothAccepted() = runBlocking {
        val fx = fixture()
        val enc = encKey()
        val presentation = fx.held(MdocDeviceAuthMode.Signature).present(ctx(fx, enc, listOf(MAC_P256, ES256)))
        val doc = (map(CborDecoder.decode(Base64Url.decode(presentation)), "documents") as Cbor.Array).items.single()
        val deviceAuth = map(map(doc, "deviceSigned")!!, "deviceAuth")!!
        assertNotNull(map(deviceAuth, "deviceSignature"), "default preference signs when signature is accepted")
        assertNull(map(deviceAuth, "deviceMac"))
    }

    @Test
    fun fallsBackToSignatureWhenResponseUnencrypted() = runBlocking {
        // No verifier encryption key → no EReaderKey → deviceMac impossible; the MAC preference still signs.
        val fx = fixture()
        val presentation = fx.held(MdocDeviceAuthMode.Mac).present(ctx(fx, encKey = null, algs = listOf(MAC_P256, ES256)))
        val doc = (map(CborDecoder.decode(Base64Url.decode(presentation)), "documents") as Cbor.Array).items.single()
        assertNotNull(map(map(map(doc, "deviceSigned")!!, "deviceAuth")!!, "deviceSignature"))
    }

    @Test
    fun failsWhenVerifierRequiresMacButKeyCannotAgree() = runBlocking {
        // deviceauth_alg_values excludes any signature the wallet can produce, and the DeviceKey cannot ECDH.
        val fx = fixture()
        val enc = encKey()
        assertFailsWith<VpException.Unsupported> {
            fx.held(MdocDeviceAuthMode.Mac, keyAgree = false).present(ctx(fx, enc, listOf(MAC_P256)))
        }
    }

    @Test
    fun clientPlumbsDeviceMacOverEncryptedDcApi() = runBlocking {
        // End to end through Openid4VpClient: deviceauth_alg_values parsed, verifier enc key wired as EReaderKey,
        // response encrypted; decrypt and confirm the vp_token carries a deviceMac.
        val fx = fixture()
        val recipient = JweRecipientKey.generate(EcCurve.P256)
        val enc = recipient.publicKey
        val jwks = """{"jwks":{"keys":[{"kty":"EC","crv":"P-256","use":"enc","alg":"ECDH-ES","kid":"enc-1",""" +
            """"x":"${Base64Url.encode(enc.x)}","y":"${Base64Url.encode(enc.y)}"}]},""" +
            """"encrypted_response_enc_values_supported":["A128GCM"],""" +
            """"vp_formats_supported":{"mso_mdoc":{"deviceauth_alg_values":[$MAC_P256]}}}"""
        val requestJson = """{"response_type":"vp_token","response_mode":"dc_api.jwt","nonce":"dcapi-nonce",
            "client_metadata":$jwks,
            "dcql_query":{"credentials":[{"id":"query_0","format":"mso_mdoc","meta":{"doctype_value":"$docType"},
            "claims":[{"path":["$namespace","family_name"]},{"path":["$namespace","given_name"]}]}]}}"""

        val client = Openid4VpClient(noHttp, clock = { 1_700_000_000 })
        val request = client.resolveDcApiRequest(requestJson, origin)
        val held = fx.held(MdocDeviceAuthMode.Signature)   // preference irrelevant: only MAC is accepted → forced
        val matches = client.match(request, listOf(held))
        val response = client.respondDcApi(request, matches, PresentationSelection.auto(matches), listOf(held))

        val plaintext = recipient.decrypt((response["response"] as JsonValue.Str).value).decodeToString()
        val vpToken = (JsonValue.parse(plaintext) as JsonValue.Obj)["vp_token"] as JsonValue.Obj
        val presentation = ((vpToken["query_0"] as JsonValue.Arr).items[0] as JsonValue.Str).value
        val doc = (map(CborDecoder.decode(Base64Url.decode(presentation)), "documents") as Cbor.Array).items.single()
        assertNotNull(map(map(map(doc, "deviceSigned")!!, "deviceAuth")!!, "deviceMac"), "encrypted DC API response carries a deviceMac")
    }

    private val noHttp = object : com.hopae.eudi.wallet.spi.HttpTransport {
        override suspend fun execute(request: com.hopae.eudi.wallet.spi.HttpRequest): com.hopae.eudi.wallet.spi.HttpResponse =
            throw AssertionError("DC API must not do HTTP")
    }
}
