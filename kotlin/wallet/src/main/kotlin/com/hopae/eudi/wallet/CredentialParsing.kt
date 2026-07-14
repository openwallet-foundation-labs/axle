package com.hopae.eudi.wallet

import com.hopae.eudi.wallet.mdoc.IssuerSigned
import com.hopae.eudi.wallet.sdjwt.JsonValue
import com.hopae.eudi.wallet.sdjwt.SdJwt
import com.hopae.eudi.wallet.sdjwt.SdJwtHolder
import com.hopae.eudi.wallet.spi.CredentialFormat
import com.hopae.eudi.wallet.store.CredentialEnvelope
import com.hopae.eudi.wallet.store.EnvelopeLifecycle
import com.hopae.eudi.wallet.vp.HeldMdoc
import com.hopae.eudi.wallet.vp.QueryableCredential

/**
 * Parses a stored envelope's payload into the disclosed claims tree — no signer needed (read side).
 * Payload convention: SD-JWT VC = compact string bytes; mdoc = IssuerSigned CBOR.
 */
internal fun CredentialEnvelope.claimsTree(): JsonValue.Obj? {
    val issued = lifecycle as? EnvelopeLifecycle.Issued ?: return null
    val payload = issued.instances.firstOrNull()?.payload ?: return null
    // Degrade gracefully: a single corrupt payload must not break list()/match() over all credentials.
    return runCatching {
        when (format) {
            is CredentialFormat.SdJwtVc -> SdJwtHolder.processedClaims(SdJwt.parse(payload.decodeToString()))
            is CredentialFormat.MsoMdoc -> HeldMdoc(id.value, IssuerSigned.decode(payload)).claims
        }
    }.getOrNull()
}

/** A stored credential exposed to the DCQL engine (read-only; presentation adds a signer in Phase C). */
internal fun CredentialEnvelope.toQueryable(): QueryableCredential? {
    val claimsObj = claimsTree() ?: return null
    val env = this
    return object : QueryableCredential {
        override val credentialId: String = env.id.value
        override val format: String = when (env.format) {
            is CredentialFormat.SdJwtVc -> "dc+sd-jwt"
            is CredentialFormat.MsoMdoc -> "mso_mdoc"
        }
        override val vct: String? = (env.format as? CredentialFormat.SdJwtVc)?.vct
        override val docType: String? = (env.format as? CredentialFormat.MsoMdoc)?.docType
        override val claims: JsonValue.Obj = claimsObj
    }
}

/** Assembles the format-agnostic [Credential] view (with parsed claims) from a storage envelope. */
internal fun CredentialEnvelope.toCredential(): Credential = Credential(
    id = id,
    format = format,
    createdAt = createdAt,
    issuer = metadata?.let { IssuerInfo(it.issuerUrl, it.issuerDisplayName, it.issuerTrusted, it.issuerRegistered) },
    display = metadata?.let { CredentialDisplay(it.displayName, it.logoUri, it.backgroundColor) },
    configurationId = metadata?.configurationId,
    lifecycle = when (val lc = lifecycle) {
        is EnvelopeLifecycle.Issued -> Lifecycle.Issued(
            claims = claimsTree()?.let { flattenClaims(it, format) } ?: emptyList(),
            validity = null, // validity slice
            instances = CredentialInstances(remaining = lc.instances.size, use = lc.policy.use),
        )
        is EnvelopeLifecycle.Deferred -> Lifecycle.Deferred(lc.retryAfter)
        is EnvelopeLifecycle.Pending -> Lifecycle.Pending(lc.authorizationUrl)
    },
)

/** Flattens a claims tree into path-addressed leaf claims (nested objects → deeper paths), classifying each. */
internal fun flattenClaims(obj: JsonValue.Obj, format: CredentialFormat, prefix: List<String> = emptyList()): List<Claim> =
    obj.entries.flatMap { (key, value) ->
        val path = prefix + key
        when (value) {
            is JsonValue.Obj -> flattenClaims(value, format, path)
            else -> {
                val raw = jsonToPlain(value)
                listOf(Claim(path, ClaimValue(raw, kindOf(raw, key)), categoryOf(format, path)))
            }
        }
    }

/** SD-JWT VC registered / JWT claims that carry credential metadata rather than subject data. */
private val JWT_REGISTERED = setOf("iss", "sub", "aud", "exp", "nbf", "iat", "jti", "cnf", "vct", "status")

/** ARF/ISO administrative element names (both formats) — issuance/validity, issuing party, document identity. */
private val ADMIN_ELEMENTS = setOf(
    "issue_date", "issuance_date", "date_of_issuance", "expiry_date", "expiration_date", "valid_from", "valid_until",
    "issuing_authority", "issuing_country", "issuing_jurisdiction",
    "document_number", "administrative_number", "un_distinguishing_sign", "portrait_capture_date", "version",
)

private fun categoryOf(format: CredentialFormat, path: List<String>): ClaimCategory {
    // SD-JWT VC: anything under a top-level registered claim is metadata — checked on the ROOT key so the
    // nested children of object claims (cnf → jwk → …, status → status_list → …) are classified too.
    if (format is CredentialFormat.SdJwtVc && path.first().lowercase() in JWT_REGISTERED) return ClaimCategory.Metadata
    // Administrative data elements, either format (matched on the leaf name).
    if (path.last().lowercase() in ADMIN_ELEMENTS) return ClaimCategory.Metadata
    return ClaimCategory.Subject
}

private val DATE_RE = Regex("""^\d{4}-\d{2}-\d{2}([T ].*)?$""")
private fun kindOf(raw: Any?, key: String): ClaimValueKind = when (raw) {
    is Boolean -> ClaimValueKind.Boolean
    is Int, is Long, is Double, is Float -> ClaimValueKind.Number
    is List<*> -> ClaimValueKind.Array
    is String -> if (DATE_RE.matches(raw) || key.endsWith("_date")) ClaimValueKind.Date else ClaimValueKind.Text
    null -> ClaimValueKind.Unknown
    else -> ClaimValueKind.Text
}

private fun jsonToPlain(v: JsonValue): Any? = when (v) {
    is JsonValue.Str -> v.value
    is JsonValue.NumInt -> v.value
    is JsonValue.NumDouble -> v.value
    is JsonValue.Bool -> v.value
    JsonValue.Null -> null
    is JsonValue.Arr -> v.items.map { jsonToPlain(it) }
    is JsonValue.Obj -> v.entries.associate { (k, value) -> k to jsonToPlain(value) }
}
