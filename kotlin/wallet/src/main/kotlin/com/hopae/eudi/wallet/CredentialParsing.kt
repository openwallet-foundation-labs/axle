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
    issuer = null, // captured at issuance — metadata slice
    display = null,
    configurationId = null,
    lifecycle = when (val lc = lifecycle) {
        is EnvelopeLifecycle.Issued -> Lifecycle.Issued(
            claims = claimsTree()?.let { flattenClaims(it) } ?: emptyList(),
            validity = null, // validity slice
            instances = CredentialInstances(remaining = lc.instances.size, use = lc.policy.use),
        )
        is EnvelopeLifecycle.Deferred -> Lifecycle.Deferred(lc.retryAfter)
        is EnvelopeLifecycle.Pending -> Lifecycle.Pending(lc.authorizationUrl)
    },
)

/** Flattens a claims tree into path-addressed leaf claims (nested objects → deeper paths). */
internal fun flattenClaims(obj: JsonValue.Obj, prefix: List<String> = emptyList()): List<Claim> =
    obj.entries.flatMap { (key, value) ->
        val path = prefix + key
        when (value) {
            is JsonValue.Obj -> flattenClaims(value, path)
            else -> listOf(Claim(path, ClaimValue(jsonToPlain(value))))
        }
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
