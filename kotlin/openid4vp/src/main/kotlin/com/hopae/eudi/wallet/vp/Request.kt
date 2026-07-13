package com.hopae.eudi.wallet.vp

import com.hopae.eudi.wallet.sdjwt.Base64Url
import com.hopae.eudi.wallet.sdjwt.JsonValue
import com.hopae.eudi.wallet.sdjwt.Jws
import com.hopae.eudi.wallet.spi.HttpMethod
import com.hopae.eudi.wallet.spi.HttpRequest
import com.hopae.eudi.wallet.spi.HttpTransport
import com.hopae.eudi.wallet.spi.Rng
import java.net.URLDecoder
import java.net.URLEncoder

/** A localized string (BCP-47 `lang` + `value`) from a WRPRC `purpose` / `srv_description`. */
data class RegistrationLocalizedText(val lang: String, val value: String)

/**
 * The relying party's registration, as asserted by a registrar-issued WRPRC (ETSI TS 119 475) carried in
 * the request's `verifier_info` `registration_cert` element (ETSI TS 119 472-2 §6.3). Populated only when
 * the wallet is configured with registrar anchors and the request carries a WRPRC that validates + binds to
 * the WRPAC. The wallet layer additionally runs the Token Status List check over [status].
 */
class RegistrationInfo(
    /** `sub` — the registered semantic identifier, bound to the WRPAC organizationIdentifier (GEN-5.1.1-02). */
    val subject: String,
    /** EU-level entitlements/roles asserted for the relying party (>=1). */
    val entitlements: List<String>,
    /** The declared intended-use, localized, for the consent screen. */
    val purpose: List<RegistrationLocalizedText>,
    /** When the RP operates through an intermediary: its identifier (`intermediary.sub`) and name (`sname`). */
    val intermediarySub: String?,
    val intermediaryName: String?,
    /** The raw WRPRC `status` claim (`{ status_list: { idx, uri } }`), for the wallet-layer status check. */
    val status: JsonValue?,
)

/** What the wallet shows on the consent screen about the verifier and its trust status. */
class VerifierInfo(
    val clientId: String,
    val clientIdScheme: String,
    /** X.509 chain from the request signature, leaf-first DER (null for unsigned requests). */
    val certificateChainDer: List<ByteArray>?,
    val commonName: String?,
    /** True only when the trust verifier confirmed signature + scheme + chain to a trust anchor. */
    val trusted: Boolean,
    /** The RP's registrar-issued registration (WRPRC), when one accompanied the request and validated. */
    val registration: RegistrationInfo? = null,
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

/** The JOSE `typ` every OpenID4VP Request Object must carry (§5, RFC 9101). */
const val REQUEST_OBJECT_TYP: String = "oauth-authz-req+jwt"

/**
 * Resolves an OpenID4VP authorization request (OpenID4VP §5): parses the request URI and
 * follows JAR (`request_uri`/`request`). Signed request objects are verified through the
 * injected [RequestTrustVerifier]; without one, the request is parsed but reported untrusted.
 *
 * [rng] enables the `wallet_nonce` replay mitigation (§5.10) on `request_uri_method=post`: sending it
 * is OPTIONAL, but once sent the verifier's request object MUST echo it. Without an [rng] no nonce is
 * sent and nothing is validated.
 */
class AuthorizationRequestResolver(
    private val http: HttpTransport,
    private val trust: RequestTrustVerifier? = null,
    private val rng: Rng? = null,
) {

    suspend fun resolve(requestUri: String): ResolvedRequest {
        val params = parseQuery(requestUri)
        val clientId = params["client_id"] ?: throw VpException.InvalidRequest("missing client_id")
        val scheme = clientIdScheme(clientId)

        // §8.5 `invalid_request_uri_method`: the value is case-sensitive and must be exactly get or post.
        val uriMethod = params["request_uri_method"] ?: "get"
        if (uriMethod != "get" && uriMethod != "post") {
            throw VpException.InvalidRequest("invalid_request_uri_method: '$uriMethod' is neither get nor post")
        }
        val (claims, verifier) = when {
            params["request_uri"] != null -> {
                val walletNonce = if (uriMethod == "post") rng?.let { Base64Url.encode(it.nextBytes(16)) } else null
                verifySigned(fetchRequestObject(params["request_uri"]!!, uriMethod, walletNonce), clientId, scheme, walletNonce)
            }
            params["request"] != null -> verifySigned(params["request"]!!, clientId, scheme, null)
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
        // OpenID4VP DC API / 18013-7 C.5: the platform Origin binds the presentation (and, unsigned, is the
        // verifier's identity). A blank origin binds nothing and must be rejected before it is used.
        if (origin.isBlank()) throw VpException.InvalidRequest("DC API origin must not be blank")
        val trimmed = requestObject.trim()
        val (claims, verifier) = if (trimmed.startsWith("{")) {
            val c = JsonValue.parse(trimmed) as? JsonValue.Obj ?: throw VpException.InvalidRequest("DC API request must be JSON")
            val signedRequest = c.str("request")
            // OpenID4VP 1.0 signed DC API: data is {"request": "<JWS>"} (JAR); the claims live in the JWS.
            if (signedRequest != null) verifySignedDcApi(signedRequest, origin)
            // Unsigned (Appendix A.3.1): the Origin *is* the verifier's identity. The wallet MUST ignore
            // any `client_id` and any `expected_origins` such a request carries.
            else c to VerifierInfo(origin, "origin", null, null, trusted = false)
        } else {
            verifySignedDcApi(trimmed, origin) // bare JWS
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

    /** Signed DC API request: the client_id (and thus its prefix/scheme) come from the JWS claims, not query params. */
    private suspend fun verifySignedDcApi(jwt: String, origin: String): Pair<JsonValue.Obj, VerifierInfo> {
        val jws = Jws.parse(jwt)
        requireRequestObjectTyp(jws)
        val claims = JsonValue.parse(jws.payloadBytes.decodeToString()) as? JsonValue.Obj
            ?: throw VpException.InvalidRequest("signed DC API request payload must be JSON")
        checkExpectedOrigins(claims, origin)
        // Appendix A.2: client_id MUST be present in a signed request — it selects the Client Identifier Prefix.
        val clientId = claims.str("client_id")
            ?: throw VpException.InvalidRequest("signed DC API request has no client_id")
        // OpenID4VP 1.0: the scheme is the client_id prefix (no separate client_id_scheme parameter).
        val scheme = clientIdScheme(clientId)
        val verifier = trust?.verifyRequestObject(jws, clientId, scheme)
            ?: VerifierInfo(clientId, scheme, jws.x5c, null, trusted = false)
        return claims to verifier
    }

    /**
     * OpenID4VP Appendix A.2 — `expected_origins` is REQUIRED in signed DC API requests: the wallet MUST
     * compare it against the platform-supplied Origin "to detect replay of the request from a malicious
     * Verifier", and MUST error when no entry matches. A signature proves *who authored* a request, not
     * *where it may be used*; the signed list and the platform Origin come from two channels the calling
     * page controls neither of. Absent or empty is rejected — the guarantee cannot be evaluated.
     */
    private fun checkExpectedOrigins(claims: JsonValue.Obj, origin: String) {
        val entries = (claims["expected_origins"] as? JsonValue.Arr)?.items
            ?: throw VpException.InvalidRequest("signed DC API request has no expected_origins")
        if (entries.isEmpty()) throw VpException.InvalidRequest("expected_origins must be a non-empty array")
        val origins = entries.map {
            (it as? JsonValue.Str)?.value ?: throw VpException.InvalidRequest("expected_origins entries must be strings")
        }
        if (origin !in origins) {
            throw VpException.InvalidRequest("origin '$origin' does not match expected_origins $origins")
        }
    }

    private suspend fun verifySigned(
        jwt: String,
        clientId: String,
        scheme: String,
        walletNonce: String?,
    ): Pair<JsonValue.Obj, VerifierInfo> {
        val jws = Jws.parse(jwt)
        requireRequestObjectTyp(jws)
        val claims = JsonValue.parse(jws.payloadBytes.decodeToString()) as? JsonValue.Obj
            ?: throw VpException.InvalidRequest("request object payload must be JSON")
        // §5.10.1: the Request Object's client_id MUST equal the Authorization Request's, prefix included.
        // (An `iss` claim, if present, is ignored — §5.)
        val objectClientId = claims.str("client_id")
            ?: throw VpException.InvalidRequest("request object has no client_id")
        if (objectClientId != clientId) {
            throw VpException.InvalidRequest("request object client_id '$objectClientId' != request client_id '$clientId'")
        }
        // §5.10: having sent a wallet_nonce, the wallet MUST terminate unless the request object echoes it.
        if (walletNonce != null && claims.str("wallet_nonce") != walletNonce) {
            throw VpException.InvalidRequest("request object does not echo the wallet_nonce")
        }
        val verifier = trust?.verifyRequestObject(jws, clientId, scheme)
            ?: VerifierInfo(clientId, scheme, jws.x5c, null, trusted = false)
        return claims to verifier
    }

    /**
     * §5: "Wallets MUST NOT process Request Objects where the `typ` Header Parameter is not present or
     * does not have the value `oauth-authz-req+jwt`." Typing the JWS stops a token minted for another
     * purpose (an ID token, a key-proof JWT) from being replayed as an authorization request.
     */
    private fun requireRequestObjectTyp(jws: Jws) {
        val typ = (jws.header["typ"] as? JsonValue.Str)?.value
        if (typ != REQUEST_OBJECT_TYP) {
            throw VpException.InvalidRequest("request object typ must be '$REQUEST_OBJECT_TYP', got '${typ ?: "<missing>"}'")
        }
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
     * the wallet POSTs its capabilities as `wallet_metadata` — and, when available, a fresh
     * [walletNonce] the verifier must echo in the signed request object; otherwise it GETs the URL.
     */
    private suspend fun fetchRequestObject(url: String, method: String, walletNonce: String?): String {
        val request = if (method == "post") {
            val body = buildString {
                append("wallet_metadata=").append(enc(WALLET_METADATA))
                walletNonce?.let { append("&wallet_nonce=").append(enc(it)) }
            }.encodeToByteArray()
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

    /** OpenID4VP 1.0: the client_id scheme is its prefix (e.g. `x509_san_dns:…`), or `redirect_uri` if unprefixed. */
    private fun clientIdScheme(clientId: String): String =
        if (clientId.contains(":")) clientId.substringBefore(":") else "redirect_uri"

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
                "client_id_prefixes_supported" to JsonValue.Arr(listOf("x509_san_dns", "x509_hash", "redirect_uri").map { JsonValue.Str(it) }),
                "request_object_signing_alg_values_supported" to JsonValue.Arr(listOf(JsonValue.Str("ES256"))),
                "response_types_supported" to JsonValue.Arr(listOf(JsonValue.Str("vp_token"))),
                "response_modes_supported" to JsonValue.Arr(listOf("direct_post", "direct_post.jwt").map { JsonValue.Str(it) }),
            ),
        ).serialize()
    }
}
