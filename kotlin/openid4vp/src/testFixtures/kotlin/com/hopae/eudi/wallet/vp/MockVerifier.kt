package com.hopae.eudi.wallet.vp

import com.hopae.eudi.wallet.cbor.cose.EcCurve
import com.hopae.eudi.wallet.cbor.cose.EcPublicKey
import com.hopae.eudi.wallet.sdjwt.JsonValue
import com.hopae.eudi.wallet.sdjwt.JwkEc
import com.hopae.eudi.wallet.sdjwt.Jwe
import com.hopae.eudi.wallet.sdjwt.SdJwt
import com.hopae.eudi.wallet.sdjwt.SdJwtVerifier
import com.hopae.eudi.wallet.spi.HttpMethod
import com.hopae.eudi.wallet.spi.HttpRequest
import com.hopae.eudi.wallet.spi.HttpResponse
import com.hopae.eudi.wallet.spi.HttpTransport
import com.hopae.eudi.wallet.spi.SigningAlgorithm
import java.math.BigInteger
import java.net.URLDecoder
import java.net.URLEncoder
import java.security.KeyPairGenerator
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec

/** A mock OpenID4VP verifier (HttpTransport): builds a request, receives & verifies an SD-JWT VC response. */
class MockVerifier(
    private val issuerPublic: EcPublicKey,
    private val dcqlQuery: String = DEFAULT_PID_QUERY,
    /** When true, the verifier rejects the submitted response with HTTP 400 (e.g. issuer not trusted). */
    var rejectResponse: Boolean = false,
) : HttpTransport {
    val clientId = "verifier.example"
    val nonce = "vp-nonce-123"
    val responseUri = "https://verifier.example/response"

    private val encKp = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
    private val encPubJwk: JsonValue.Obj
    private val encPrivD: ByteArray

    var verifiedClaims: JsonValue.Obj? = null

    /** The Authorization Error Response the wallet POSTed instead of a `vp_token` (§8.5), if any. */
    class ErrorResponse(val error: String, val description: String?, val state: String?)
    var errorResponse: ErrorResponse? = null
        private set

    init {
        val pub = encKp.public as ECPublicKey
        fun fixed(b: BigInteger): ByteArray { val s = b.toByteArray().dropWhile { it == 0.toByte() }.toByteArray(); return ByteArray(32 - s.size) + s }
        val ec = EcPublicKey(EcCurve.P256, fixed(pub.w.affineX), fixed(pub.w.affineY))
        encPubJwk = JwkEc.toJson(ec).let { JsonValue.Obj(it.entries + ("use" to JsonValue.Str("enc"))) }
        encPrivD = fixed((encKp.private as ECPrivateKey).s)
    }

    fun requestUri(responseMode: String): String {
        val clientMetadata = JsonValue.Obj(
            listOf(
                "jwks" to JsonValue.Obj(listOf("keys" to JsonValue.Arr(listOf(encPubJwk)))),
                "encrypted_response_enc_values_supported" to JsonValue.Arr(listOf(JsonValue.Str("A256GCM"))),
            ),
        ).serialize()
        return "openid4vp://?client_id=${enc(clientId)}&nonce=${enc(nonce)}" +
            "&response_mode=$responseMode&response_uri=${enc(responseUri)}&state=xyz" +
            "&dcql_query=${enc(dcqlQuery)}&client_metadata=${enc(clientMetadata)}"
    }

    /**
     * An unsigned Digital Credentials API request object (Appendix A.3.1): the origin is the verifier's
     * identity, so it carries no `client_id` and no `response_uri` — nothing is ever POSTed for it.
     */
    fun dcApiRequestObject(): String = JsonValue.Obj(
        listOf(
            "response_type" to JsonValue.Str("vp_token"),
            "response_mode" to JsonValue.Str("dc_api"),
            "nonce" to JsonValue.Str(nonce),
            "dcql_query" to JsonValue.parse(DEFAULT_PID_QUERY),
        )
    ).serialize()

    override suspend fun execute(request: HttpRequest): HttpResponse {
        if (request.url != responseUri || request.method != HttpMethod.POST) return HttpResponse(404, emptyList(), ByteArray(0))
        if (rejectResponse) return HttpResponse(400, emptyList(), """{"error":"invalid_vp_token"}""".encodeToByteArray())
        val form = request.body!!.decodeToString().split('&').associate {
            URLDecoder.decode(it.substringBefore('='), "UTF-8") to URLDecoder.decode(it.substringAfter('='), "UTF-8")
        }
        // OpenID4VP §8.5: an Authorization Error Response lands on the same endpoint as the vp_token.
        form["error"]?.let { code ->
            errorResponse = ErrorResponse(code, form["error_description"], form["state"])
            return HttpResponse(200, listOf("Content-Type" to "application/json"), """{"redirect_uri":"https://verifier.example/done"}""".encodeToByteArray())
        }
        val vpTokenJson = when {
            form["response"] != null -> Jwe.decryptEcdhEs(form["response"]!!, encPrivD, EcCurve.P256).decodeToString()
                .let { JsonValue.parse(it) as JsonValue.Obj }.let { it["vp_token"] as JsonValue.Obj }
            form["vp_token"] != null -> JsonValue.parse(form["vp_token"]!!) as JsonValue.Obj
            else -> error("no vp_token in response")
        }
        val presentation = ((vpTokenJson["pid"] as JsonValue.Arr).items.first() as JsonValue.Str).value
        val verified = SdJwtVerifier.verify(
            SdJwt.parse(presentation), issuerPublic, SigningAlgorithm.ES256,
            keyBinding = SdJwtVerifier.KbRequirement(clientId, nonce),
        )
        verifiedClaims = verified.claims
        return HttpResponse(200, listOf("Content-Type" to "application/json"), """{"redirect_uri":"https://verifier.example/done"}""".encodeToByteArray())
    }

    companion object {
        const val DEFAULT_PID_QUERY = """{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:eudi:pid:1"]},"claims":[{"path":["family_name"]},{"path":["given_name"]}]}]}"""
        private fun enc(s: String) = URLEncoder.encode(s, "UTF-8")
    }
}
