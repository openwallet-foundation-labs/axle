package com.hopae.eudi.wallet.vp

import com.hopae.eudi.wallet.cbor.Cbor
import com.hopae.eudi.wallet.cbor.CborDecoder
import com.hopae.eudi.wallet.cbor.CborEncoder
import com.hopae.eudi.wallet.cbor.cose.CoseSign1
import com.hopae.eudi.wallet.mdoc.IssuerSigned
import com.hopae.eudi.wallet.sdjwt.Base64Url
import com.hopae.eudi.wallet.sdjwt.JsonValue
import com.hopae.eudi.wallet.spi.HttpMethod
import com.hopae.eudi.wallet.spi.HttpRequest
import com.hopae.eudi.wallet.spi.HttpResponse
import com.hopae.eudi.wallet.spi.HttpTransport
import java.net.URLDecoder
import java.net.URLEncoder

/**
 * A mock OpenID4VP verifier for mdoc: serves an mso_mdoc DCQL query and verifies the returned
 * DeviceResponse — device signature over the OID4VP SessionTranscript, using the deviceKey from the MSO.
 * Unencrypted (`direct_post`) for simplicity.
 */
class MockMdocVerifier(
    val docType: String = "org.iso.18013.5.1.mDL",
    val namespace: String = "org.iso.18013.5.1",
) : HttpTransport {
    val clientId = "verifier.example"
    val nonce = "vp-nonce-mdoc"
    val responseUri = "https://verifier.example/response"

    /** Element identifiers disclosed by the last verified DeviceResponse. */
    var disclosedElements: Set<String>? = null
        private set

    fun requestUri(): String {
        val dcql = """{"credentials":[{"id":"mdl","format":"mso_mdoc","meta":{"doctype_value":"$docType"},""" +
            """"claims":[{"path":["$namespace","family_name"]},{"path":["$namespace","given_name"]}]}]}"""
        return "openid4vp://?client_id=${enc(clientId)}&nonce=${enc(nonce)}" +
            "&response_mode=direct_post&response_uri=${enc(responseUri)}&state=xyz&dcql_query=${enc(dcql)}"
    }

    override suspend fun execute(request: HttpRequest): HttpResponse {
        if (request.url != responseUri || request.method != HttpMethod.POST) return HttpResponse(404, emptyList(), ByteArray(0))
        val form = request.body!!.decodeToString().split('&').associate {
            URLDecoder.decode(it.substringBefore('='), "UTF-8") to URLDecoder.decode(it.substringAfter('='), "UTF-8")
        }
        val vpToken = JsonValue.parse(form["vp_token"]!!) as JsonValue.Obj
        val presentation = ((vpToken["mdl"] as JsonValue.Arr).items.first() as JsonValue.Str).value
        val deviceResponse = CborDecoder.decode(Base64Url.decode(presentation))

        val document = (map(deviceResponse, "documents") as Cbor.Array).items.single()
        val issuerSigned = IssuerSigned.fromCbor(map(document, "issuerSigned")!!)
        val deviceKey = issuerSigned.parseMso().deviceKey

        // device signature over the reconstructed DeviceAuthenticationBytes (thumbprint null for direct_post)
        val deviceSigned = map(document, "deviceSigned")!!
        val deviceSignature = CoseSign1.fromCbor(map(map(deviceSigned, "deviceAuth")!!, "deviceSignature")!!)
        val sessionTranscript = Oid4vpSessionTranscript.build(clientId, responseUri, nonce, null)
        val deviceNameSpacesBytes = map(deviceSigned, "nameSpaces")!!
        val deviceAuth = Cbor.Array(listOf(Cbor.Text("DeviceAuthentication"), sessionTranscript, Cbor.Text(docType), deviceNameSpacesBytes))
        val deviceAuthBytes = CborEncoder.encode(Cbor.Tagged(24u, Cbor.Bytes(CborEncoder.encode(deviceAuth))))
        require(deviceSignature.verify(deviceKey, detachedPayload = deviceAuthBytes)) { "device signature must verify" }

        disclosedElements = issuerSigned.nameSpaces[namespace]!!.map { it.item.elementIdentifier }.toSet()
        return HttpResponse(200, listOf("Content-Type" to "application/json"), """{"redirect_uri":"https://verifier.example/done"}""".encodeToByteArray())
    }

    private fun map(c: Cbor, key: String): Cbor? =
        (c as Cbor.CborMap).entries.firstOrNull { (k, _) -> (k as? Cbor.Text)?.value == key }?.second

    private companion object {
        fun enc(s: String) = URLEncoder.encode(s, "UTF-8")
    }
}
