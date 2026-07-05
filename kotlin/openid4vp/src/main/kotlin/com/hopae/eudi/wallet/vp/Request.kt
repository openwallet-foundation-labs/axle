package com.hopae.eudi.wallet.vp

import com.hopae.eudi.wallet.sdjwt.JsonValue
import com.hopae.eudi.wallet.sdjwt.Jws
import com.hopae.eudi.wallet.spi.HttpMethod
import com.hopae.eudi.wallet.spi.HttpRequest
import com.hopae.eudi.wallet.spi.HttpTransport
import java.net.URLDecoder
import java.net.URLEncoder

/** What the wallet shows on the consent screen about the verifier and its trust status. */
class VerifierInfo(
    val clientId: String,
    val clientIdScheme: String,
    /** X.509 chain from the request signature, leaf-first DER (null for unsigned requests). */
    val certificateChainDer: List<ByteArray>?,
    val commonName: String?,
    /** True only when the trust verifier confirmed signature + scheme + chain to a trust anchor. */
    val trusted: Boolean,
)

/**
 * Verifies an OpenID4VP signed request object: the JWS signature, the client_id scheme
 * (x509_san_dns / x509_hash), and the certificate chain to a trust anchor. Implemented by
 * the `trust` module (X.509 lives there); the resolver stays platform-neutral.
 */
interface RequestTrustVerifier {
    suspend fun verifyRequestObject(jws: Jws, clientId: String, scheme: String): VerifierInfo
}

class ResolvedRequest(
    val clientId: String,
    val nonce: String,
    val state: String?,
    val responseMode: String,
    val responseUri: String?,
    val redirectUri: String?,
    val dcqlQuery: DcqlQuery,
    val clientMetadata: JsonValue.Obj?,
    val transactionData: List<String>?,
    val verifier: VerifierInfo,
    /** Caller web origin for a Digital Credentials API request (null for the URL/QR flow). */
    val origin: String? = null,
)

/**
 * Resolves an OpenID4VP authorization request (OpenID4VP §5): parses the request URI and
 * follows JAR (`request_uri`/`request`). Signed request objects are verified through the
 * injected [RequestTrustVerifier]; without one, the request is parsed but reported untrusted.
 */
class AuthorizationRequestResolver(
    private val http: HttpTransport,
    private val trust: RequestTrustVerifier? = null,
) {

    suspend fun resolve(requestUri: String): ResolvedRequest {
        val params = parseQuery(requestUri)
        val clientId = params["client_id"] ?: throw VpException.InvalidRequest("missing client_id")
        val scheme = clientIdScheme(clientId, params["client_id_scheme"])

        val uriMethod = params["request_uri_method"]?.lowercase() ?: "get"
        val (claims, verifier) = when {
            params["request_uri"] != null -> verifySigned(fetchRequestObject(params["request_uri"]!!, uriMethod), clientId, scheme)
            params["request"] != null -> verifySigned(params["request"]!!, clientId, scheme)
            else -> unsignedRequest(params) to VerifierInfo(clientId, scheme, null, null, trusted = false)
        }
        return build(claims, clientId, scheme, verifier)
    }

    /**
     * Resolves an OpenID4VP request delivered over the W3C Digital Credentials API. The request
     * object (unsigned JSON or a signed JWS) has no `response_uri`; [origin] is supplied by the
     * platform and binds the presentation. Uses `dc_api` / `dc_api.jwt` response modes.
     */
    suspend fun resolveDcApi(requestObject: String, origin: String): ResolvedRequest {
        val trimmed = requestObject.trim()
        val (claims, verifier) = if (trimmed.startsWith("{")) {
            val c = JsonValue.parse(trimmed) as? JsonValue.Obj ?: throw VpException.InvalidRequest("DC API request must be JSON")
            val clientId = c.str("client_id") ?: origin
            c to VerifierInfo(clientId, "web-origin", null, null, trusted = false)
        } else {
            val clientIdHint = origin
            val (c, v) = verifySigned(trimmed, clientIdHint, "x509_san_dns")
            c to VerifierInfo(c.str("client_id") ?: clientIdHint, v.clientIdScheme, v.certificateChainDer, v.commonName, v.trusted)
        }
        return build(claims, verifier.clientId, verifier.clientIdScheme, verifier, origin)
    }

    private fun build(claims: JsonValue.Obj, clientId: String, scheme: String, verifier: VerifierInfo, origin: String? = null): ResolvedRequest {
        val nonce = claims.str("nonce") ?: throw VpException.InvalidRequest("missing nonce")
        val dcqlObj = claims["dcql_query"] as? JsonValue.Obj
            ?: throw VpException.InvalidRequest("missing dcql_query (only DCQL is supported)")
        val responseMode = claims.str("response_mode") ?: if (origin != null) "dc_api" else "direct_post"
        val allowed = setOf("direct_post", "direct_post.jwt", "dc_api", "dc_api.jwt")
        if (responseMode !in allowed) throw VpException.Unsupported("response_mode '$responseMode'")
        val txData = (claims["transaction_data"] as? JsonValue.Arr)?.items?.mapNotNull { (it as? JsonValue.Str)?.value }
        return ResolvedRequest(
            clientId = clientId,
            nonce = nonce,
            state = claims.str("state"),
            responseMode = responseMode,
            responseUri = claims.str("response_uri"),
            redirectUri = claims.str("redirect_uri"),
            dcqlQuery = DcqlQuery.parse(dcqlObj),
            clientMetadata = claims["client_metadata"] as? JsonValue.Obj,
            transactionData = txData,
            verifier = verifier,
            origin = origin,
        )
    }

    private suspend fun verifySigned(jwt: String, clientId: String, scheme: String): Pair<JsonValue.Obj, VerifierInfo> {
        val jws = Jws.parse(jwt)
        val claims = JsonValue.parse(jws.payloadBytes.decodeToString()) as? JsonValue.Obj
            ?: throw VpException.InvalidRequest("request object payload must be JSON")
        val verifier = trust?.verifyRequestObject(jws, clientId, scheme)
            ?: VerifierInfo(clientId, scheme, jws.x5c, null, trusted = false)
        return claims to verifier
    }

    private fun unsignedRequest(params: Map<String, String>): JsonValue.Obj = JsonValue.Obj(
        params.map { (k, v) ->
            k to when (k) {
                "dcql_query", "client_metadata", "transaction_data" -> JsonValue.parse(v)
                else -> JsonValue.Str(v)
            }
        }
    )

    /**
     * Fetches the request object from `request_uri`. With `request_uri_method=post` (OpenID4VP §5.10)
     * the wallet POSTs its capabilities as `wallet_metadata` so the verifier can tailor the request;
     * otherwise it GETs the URL.
     */
    private suspend fun fetchRequestObject(url: String, method: String): String {
        val request = if (method == "post") {
            val body = "wallet_metadata=${enc(WALLET_METADATA)}".encodeToByteArray()
            HttpRequest(
                HttpMethod.POST, url,
                listOf(
                    "Accept" to "application/oauth-authz-req+jwt",
                    "Content-Type" to "application/x-www-form-urlencoded",
                ),
                body,
            )
        } else {
            HttpRequest(HttpMethod.GET, url, listOf("Accept" to "application/oauth-authz-req+jwt"))
        }
        val resp = http.execute(request)
        if (resp.status !in 200..299) throw VpException.InvalidRequest("request_uri fetch failed: HTTP ${resp.status}")
        return resp.body.decodeToString().trim()
    }

    private fun clientIdScheme(clientId: String, explicit: String?): String = when {
        explicit != null -> explicit
        clientId.contains(":") -> clientId.substringBefore(":")
        else -> "redirect_uri"
    }

    private fun parseQuery(uri: String): Map<String, String> {
        val query = uri.substringAfter('?', "")
        if (query.isEmpty()) throw VpException.InvalidRequest("no query parameters in request")
        return query.split('&').filter { it.isNotEmpty() }.associate {
            URLDecoder.decode(it.substringBefore('='), "UTF-8") to URLDecoder.decode(it.substringAfter('=', ""), "UTF-8")
        }
    }

    private fun JsonValue.Obj.str(name: String): String? = (this[name] as? JsonValue.Str)?.value

    private fun enc(s: String): String = URLEncoder.encode(s, "UTF-8")

    private companion object {
        /** Wallet capabilities advertised to the verifier for `request_uri_method=post`. */
        val WALLET_METADATA: String = JsonValue.Obj(
            listOf(
                "vp_formats_supported" to JsonValue.Obj(
                    listOf(
                        "dc+sd-jwt" to JsonValue.Obj(
                            listOf(
                                "sd-jwt_alg_values" to JsonValue.Arr(listOf(JsonValue.Str("ES256"))),
                                "kb-jwt_alg_values" to JsonValue.Arr(listOf(JsonValue.Str("ES256"))),
                            ),
                        ),
                        "mso_mdoc" to JsonValue.Obj(listOf("alg_values" to JsonValue.Arr(listOf(JsonValue.Str("ES256"))))),
                    ),
                ),
                "client_id_schemes_supported" to JsonValue.Arr(listOf("x509_san_dns", "x509_hash", "redirect_uri").map { JsonValue.Str(it) }),
                "request_object_signing_alg_values_supported" to JsonValue.Arr(listOf(JsonValue.Str("ES256"))),
                "response_types_supported" to JsonValue.Arr(listOf(JsonValue.Str("vp_token"))),
                "response_modes_supported" to JsonValue.Arr(listOf("direct_post", "direct_post.jwt").map { JsonValue.Str(it) }),
            ),
        ).serialize()
    }
}
