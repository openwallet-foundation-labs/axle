package com.hopae.eudi.wallet.vp

import com.hopae.eudi.wallet.sdjwt.JsonValue
import com.hopae.eudi.wallet.sdjwt.JwkEc
import com.hopae.eudi.wallet.sdjwt.Jwe
import com.hopae.eudi.wallet.sdjwt.JweEnc
import com.hopae.eudi.wallet.spi.HttpMethod
import com.hopae.eudi.wallet.spi.HttpRequest
import com.hopae.eudi.wallet.spi.HttpTransport
import java.net.URLEncoder

/** Per-query choice: which held credential to present for a DCQL credential-query id. */
class PresentationSelection(val chosen: Map<String, String>) {
    companion object {
        /** Auto-pick the first candidate for every required query. */
        fun auto(matches: DcqlMatchResult): PresentationSelection {
            val chosen = matches.requiredQueryIds.mapNotNull { qid ->
                matches.candidatesByQuery[qid]?.firstOrNull()?.let { qid to it.credential.credentialId }
            }.toMap()
            return PresentationSelection(chosen)
        }
    }
}

/** Outcome of submitting the presentation. */
class SubmitResult(val redirectUri: String?)

/**
 * OpenID4VP 1.0 client (wallet/holder side) over the [HttpTransport] port. Resolves the
 * request, runs DCQL matching, builds the `vp_token`, and submits via `direct_post` or the
 * encrypted `direct_post.jwt` (JWE). SD-JWT VC presentations; mdoc arrives with M4.
 */
class Openid4VpClient(
    private val http: HttpTransport,
    /** epoch seconds; injectable for deterministic tests. */
    private val clock: () -> Long,
    /** Trust verifier for signed request objects (from the `trust` module); null = parse untrusted. */
    trust: RequestTrustVerifier? = null,
) {
    private val resolver = AuthorizationRequestResolver(http, trust)

    suspend fun resolveRequest(requestUri: String): ResolvedRequest = resolver.resolve(requestUri)

    fun match(request: ResolvedRequest, held: List<HeldSdJwtVc>): DcqlMatchResult =
        DcqlEngine.match(request.dcqlQuery, held)

    /**
     * Builds the presentations for [selection] and submits them. Throws
     * [VpException.QueryNotSatisfiable] if a required query has no chosen candidate.
     */
    suspend fun respond(
        request: ResolvedRequest,
        matches: DcqlMatchResult,
        selection: PresentationSelection,
        held: List<HeldSdJwtVc>,
    ): SubmitResult {
        val missing = matches.requiredQueryIds.filter { it !in selection.chosen }.toSet()
        if (missing.isNotEmpty()) throw VpException.QueryNotSatisfiable(missing)

        val heldById = held.associateBy { it.credentialId }
        val iat = clock()

        // vp_token: query id -> [presentation string]
        val vpEntries = mutableListOf<Pair<String, JsonValue>>()
        for ((queryId, credentialId) in selection.chosen) {
            val candidate = matches.candidatesByQuery[queryId]?.firstOrNull { it.credential.credentialId == credentialId }
                ?: throw VpException.SelectionIncomplete("no candidate $credentialId for query $queryId")
            val cred = heldById[credentialId] ?: throw VpException.SelectionIncomplete("unknown credential $credentialId")
            val presentation = cred.present(
                disclosedPaths = candidate.disclosedPaths,
                audience = request.clientId,
                nonce = request.nonce,
                issuedAt = iat,
                transactionData = request.transactionData,
            )
            vpEntries.add(queryId to JsonValue.Arr(listOf(JsonValue.Str(presentation))))
        }
        val vpToken = JsonValue.Obj(vpEntries)

        return when (request.responseMode) {
            "direct_post" -> submitDirectPost(request, vpToken)
            "direct_post.jwt" -> submitDirectPostJwt(request, vpToken)
            else -> throw VpException.Unsupported("response_mode ${request.responseMode}")
        }
    }

    private suspend fun submitDirectPost(request: ResolvedRequest, vpToken: JsonValue.Obj): SubmitResult {
        val form = buildString {
            append("vp_token=").append(enc(vpToken.serialize()))
            request.state?.let { append("&state=").append(enc(it)) }
        }
        return post(request.responseUri ?: throw VpException.InvalidRequest("direct_post needs response_uri"), form)
    }

    private suspend fun submitDirectPostJwt(request: ResolvedRequest, vpToken: JsonValue.Obj): SubmitResult {
        val recipient = verifierEncryptionKey(request)
            ?: throw VpException.InvalidRequest("direct_post.jwt but no verifier encryption key in client_metadata")
        val enc = encValue(request)
        val response = JsonValue.Obj(
            buildList {
                add("vp_token" to vpToken)
                request.state?.let { add("state" to JsonValue.Str(it)) }
            }
        )
        val jwe = Jwe.encryptEcdhEs(response.serialize().encodeToByteArray(), recipient, enc)
        val form = "response=" + enc(jwe)
        return post(request.responseUri ?: throw VpException.InvalidRequest("direct_post.jwt needs response_uri"), form)
    }

    private suspend fun post(url: String, form: String): SubmitResult {
        val resp = http.execute(
            HttpRequest(
                HttpMethod.POST, url,
                listOf("Content-Type" to "application/x-www-form-urlencoded", "Accept" to "application/json"),
                form.encodeToByteArray(),
            )
        )
        if (resp.status !in 200..299) {
            throw VpException.ResponseFailed("verifier returned HTTP ${resp.status}: ${resp.body.decodeToString().take(300)}")
        }
        val body = runCatching { JsonValue.parse(resp.body.decodeToString()) as? JsonValue.Obj }.getOrNull()
        return SubmitResult(redirectUri = (body?.get("redirect_uri") as? JsonValue.Str)?.value)
    }

    private fun verifierEncryptionKey(request: ResolvedRequest): com.hopae.eudi.wallet.cbor.cose.EcPublicKey? {
        val jwks = request.clientMetadata?.get("jwks") as? JsonValue.Obj ?: return null
        val keys = (jwks["keys"] as? JsonValue.Arr)?.items?.filterIsInstance<JsonValue.Obj>() ?: return null
        val encKey = keys.firstOrNull { (it["use"] as? JsonValue.Str)?.value == "enc" } ?: keys.firstOrNull()
        return encKey?.let { JwkEc.fromJson(it) }
    }

    private fun encValue(request: ResolvedRequest): JweEnc {
        val id = (request.clientMetadata?.get("encrypted_response_enc_values_supported") as? JsonValue.Arr)
            ?.items?.mapNotNull { (it as? JsonValue.Str)?.value }?.firstOrNull()
            ?: (request.clientMetadata?.get("authorization_encrypted_response_enc") as? JsonValue.Str)?.value
        return id?.let { JweEnc.from(it) } ?: JweEnc.A128GCM
    }

    private fun enc(v: String): String = URLEncoder.encode(v, "UTF-8")
}
