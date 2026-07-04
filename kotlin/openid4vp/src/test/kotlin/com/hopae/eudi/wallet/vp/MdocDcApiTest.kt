package com.hopae.eudi.wallet.vp

import com.hopae.eudi.wallet.cbor.Cbor
import com.hopae.eudi.wallet.cbor.CborDecoder
import com.hopae.eudi.wallet.cbor.CborEncoder
import com.hopae.eudi.wallet.cbor.cose.CoseSign1
import com.hopae.eudi.wallet.mdoc.IssuerSigned
import com.hopae.eudi.wallet.mdoc.MdocTestIssuer
import com.hopae.eudi.wallet.sdjwt.Base64Url
import com.hopae.eudi.wallet.sdjwt.JsonValue
import com.hopae.eudi.wallet.spi.HttpRequest
import com.hopae.eudi.wallet.spi.HttpResponse
import com.hopae.eudi.wallet.spi.HttpTransport
import com.hopae.eudi.wallet.spi.KeySpec
import com.hopae.eudi.wallet.spi.SecureAreaCoseSigner
import com.hopae.eudi.wallet.spi.SigningAlgorithm
import com.hopae.eudi.wallet.testkit.SoftwareSecureArea
import kotlinx.coroutines.runBlocking
import java.time.Instant
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class MdocDcApiTest {

    private val docType = "org.iso.18013.5.1.mDL"
    private val namespace = "org.iso.18013.5.1"
    private val origin = "https://verifier.example"

    private val noHttp = object : HttpTransport {
        override suspend fun execute(request: HttpRequest): HttpResponse = throw AssertionError("DC API must not do HTTP")
    }

    private fun map(c: Cbor, key: String): Cbor? =
        (c as Cbor.CborMap).entries.firstOrNull { (k, _) -> (k as? Cbor.Text)?.value == key }?.second

    private fun heldMdoc(): Pair<HeldMdoc, com.hopae.eudi.wallet.cbor.cose.EcPublicKey> = runBlocking {
        val area = SoftwareSecureArea()
        val issuerKey = area.createKey(KeySpec(secureArea = area.id, algorithm = SigningAlgorithm.ES256))
        val deviceKey = area.createKey(KeySpec(secureArea = area.id, algorithm = SigningAlgorithm.ES256))
        val bytes = MdocTestIssuer.issue(
            area = area, issuerKey = issuerKey, deviceKey = deviceKey.publicKey, docType = docType, namespace = namespace,
            elements = listOf("family_name" to Cbor.Text("Han"), "given_name" to Cbor.Text("Jongho"), "age_over_18" to Cbor.Bool(true)),
            x5chain = listOf(byteArrayOf(0x30, 0x01)),
            signed = Instant.parse("2026-01-01T00:00:00Z"), validFrom = Instant.parse("2026-01-01T00:00:00Z"), validUntil = Instant.parse("2027-01-01T00:00:00Z"),
        )
        HeldMdoc("mdl-1", IssuerSigned.decode(bytes), SecureAreaCoseSigner(area, deviceKey.handle, SigningAlgorithm.ES256)) to deviceKey.publicKey
    }

    private fun dcApiRequest(responseMode: String = "dc_api", clientMetadata: String? = null): String {
        val cm = clientMetadata?.let { ""","client_metadata":$it""" } ?: ""
        return """{"response_type":"vp_token","response_mode":"$responseMode","nonce":"dcapi-nonce",
            "dcql_query":{"credentials":[{"id":"query_0","format":"mso_mdoc","meta":{"doctype_value":"$docType"},
            "claims":[{"path":["$namespace","family_name"]},{"path":["$namespace","given_name"]}]}]}$cm}"""
    }

    @Test
    fun dcApiHandoverHasOriginBoundStructure() {
        val st = Oid4vpSessionTranscript.dcApi(origin, "nonce-x", null) as Cbor.Array
        assertEquals(Cbor.Null, st.items[0]); assertEquals(Cbor.Null, st.items[1])
        val handover = st.items[2] as Cbor.Array
        assertEquals(Cbor.Text("OpenID4VPDCAPIHandover"), handover.items[0])
        assertEquals(32, (handover.items[1] as Cbor.Bytes).value.size) // SHA-256

        val iso = com.hopae.eudi.wallet.mdoc.MdocSessionTranscript.dcApiIsoMdoc("ZW5j", origin) as Cbor.Array
        assertEquals(Cbor.Text("dcapi"), (iso.items[2] as Cbor.Array).items[0])
    }

    @Test
    fun resolvesAndPresentsMdocOverDcApi() = runBlocking {
        val (held, deviceKey) = heldMdoc()
        val client = Openid4VpClient(noHttp, clock = { 1_700_000_000 })

        val request = client.resolveDcApiRequest(dcApiRequest(), origin)
        assertEquals(origin, request.origin)
        assertEquals("dc_api", request.responseMode)

        val matches = client.match(request, listOf(held))
        assertTrue(matches.isSatisfiable())
        val response = client.respondDcApi(request, matches, PresentationSelection.auto(matches), listOf(held))

        val vpToken = response["vp_token"] as JsonValue.Obj
        val presentation = ((vpToken["query_0"] as JsonValue.Arr).items[0] as JsonValue.Str).value
        val deviceResponse = CborDecoder.decode(Base64Url.decode(presentation))
        val document = (map(deviceResponse, "documents") as Cbor.Array).items.single()

        // selective disclosure preserved
        val disclosed = IssuerSigned.fromCbor(map(document, "issuerSigned")!!).nameSpaces[namespace]!!.map { it.item.elementIdentifier }.toSet()
        assertEquals(setOf("family_name", "given_name"), disclosed)

        // deviceSignature verifies over the DC API handover SessionTranscript (origin-bound)
        val deviceSigned = map(document, "deviceSigned")!!
        val deviceSignature = CoseSign1.fromCbor(map(map(deviceSigned, "deviceAuth")!!, "deviceSignature")!!)
        val sessionTranscript = Oid4vpSessionTranscript.dcApi(origin, "dcapi-nonce", null)
        val deviceNsBytes = Cbor.Tagged(24u, Cbor.Bytes(CborEncoder.encode(Cbor.CborMap(emptyList()))))
        val deviceAuth = Cbor.Array(listOf(Cbor.Text("DeviceAuthentication"), sessionTranscript, Cbor.Text(docType), deviceNsBytes))
        val deviceAuthBytes = CborEncoder.encode(Cbor.Tagged(24u, Cbor.Bytes(CborEncoder.encode(deviceAuth))))
        assertTrue(deviceSignature.verify(deviceKey, detachedPayload = deviceAuthBytes), "deviceSignature must bind the DC API origin")
    }

    @Test
    fun dcApiJwtReturnsEncryptedResponse() = runBlocking {
        val (held, _) = heldMdoc()
        val client = Openid4VpClient(noHttp, clock = { 1_700_000_000 })
        // a real verifier encryption key (P-256, use=enc) in client_metadata
        val area = SoftwareSecureArea()
        val encKey = area.createKey(KeySpec(secureArea = area.id, algorithm = SigningAlgorithm.ES256)).publicKey
        val jwks = """{"jwks":{"keys":[{"kty":"EC","crv":"P-256","use":"enc","x":"${Base64Url.encode(encKey.x)}","y":"${Base64Url.encode(encKey.y)}"}]},"encrypted_response_enc_values_supported":["A128GCM"]}"""
        val request = client.resolveDcApiRequest(dcApiRequest("dc_api.jwt", jwks), origin)

        val matches = client.match(request, listOf(held))
        val response = client.respondDcApi(request, matches, PresentationSelection.auto(matches), listOf(held))
        val jwe = (response["response"] as JsonValue.Str).value
        assertEquals(5, jwe.split(".").size, "dc_api.jwt response is a compact JWE")
        assertTrue(response["vp_token"] == null, "encrypted response must not expose vp_token in the clear")
    }
}
