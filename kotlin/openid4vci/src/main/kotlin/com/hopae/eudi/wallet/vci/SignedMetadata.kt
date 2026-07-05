package com.hopae.eudi.wallet.vci

import com.hopae.eudi.wallet.sdjwt.JsonValue

/**
 * Verifies the issuer's `signed_metadata` JWT (OpenID4VCI §11.2.3) and returns its verified claims.
 * The adapter (app-supplied) checks the JWS signature and its x5c chain to a trust anchor — keeping
 * openid4vci decoupled from the trust module (ports & adapters).
 */
fun interface SignedMetadataVerifier {
    suspend fun verify(signedMetadataJws: String): JsonValue.Obj
}

/** How to treat the issuer's `signed_metadata` (OpenID4VCI §11.2.3). */
sealed interface IssuerMetadataPolicy {
    /** Ignore `signed_metadata`; use the fetched JSON as-is (default). */
    data object IgnoreSigned : IssuerMetadataPolicy

    /** Verify and prefer `signed_metadata` when present; fall back to the fetched JSON otherwise. */
    data class PreferSigned(val verifier: SignedMetadataVerifier) : IssuerMetadataPolicy

    /** Require verified `signed_metadata`; fail if it is absent or its verification fails. */
    data class RequireSigned(val verifier: SignedMetadataVerifier) : IssuerMetadataPolicy
}

/** Overlays verified signed-metadata claims onto the fetched JSON (verified wins); drops `signed_metadata`. */
internal fun mergeSignedMetadata(plain: JsonValue.Obj, verified: JsonValue.Obj): JsonValue.Obj {
    val order = LinkedHashSet<String>()
    plain.entries.forEach { order.add(it.first) }
    verified.entries.forEach { order.add(it.first) }
    order.remove("signed_metadata")
    val v = verified.entries.toMap()
    val p = plain.entries.toMap()
    return JsonValue.Obj(order.map { it to (v[it] ?: p.getValue(it)) })
}
