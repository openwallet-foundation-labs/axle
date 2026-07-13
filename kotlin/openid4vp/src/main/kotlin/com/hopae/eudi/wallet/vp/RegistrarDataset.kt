package com.hopae.eudi.wallet.vp

import com.hopae.eudi.wallet.sdjwt.JsonValue

/**
 * A credential (+ its claim paths) a Relying Party is registered to request — parsed from a WRPRC
 * `credentials` entry, a `registrar_dataset` `credential` entry, or a TS5 registry record. It captures
 * exactly what the RP is *allowed* to ask for, so the wallet can run the attribute-scope check
 * (ETSI TS 119 475 RPRC_21): every attribute a presentation requests must be covered by one of these.
 */
data class RegisteredCredential(
    val format: String,
    /** mdoc doctype (`meta.doctype_value`), when [format] is `mso_mdoc`. */
    val docType: String?,
    /** SD-JWT VC types (`meta.vct_values`), when [format] is `dc+sd-jwt`. */
    val vctValues: List<String>?,
    /** Each registered claim path as string segments, e.g. `["org.iso.18013.5.1","given_name"]`. */
    val claims: List<List<String>>,
) {
    companion object {
        /** Parses one `{ format, meta, claim | claims: [{ path: [...] }] }` object; null if unusable. */
        fun fromJson(o: JsonValue.Obj): RegisteredCredential? {
            val format = (o["format"] as? JsonValue.Str)?.value ?: return null
            val meta = o["meta"] as? JsonValue.Obj
            val docType = (meta?.get("doctype_value") as? JsonValue.Str)?.value
            val vctValues = (meta?.get("vct_values") as? JsonValue.Arr)?.items
                ?.mapNotNull { (it as? JsonValue.Str)?.value }
            // The registrar emits the claim list as `claim`; some producers use `claims`. Accept either.
            val claimArr = (o["claim"] as? JsonValue.Arr) ?: (o["claims"] as? JsonValue.Arr)
            val claims = claimArr?.items?.mapNotNull { c ->
                ((c as? JsonValue.Obj)?.get("path") as? JsonValue.Arr)?.items
                    ?.mapNotNull { (it as? JsonValue.Str)?.value }
            } ?: emptyList()
            return RegisteredCredential(format, docType, vctValues, claims)
        }

        fun listFromJson(arr: JsonValue.Arr?): List<RegisteredCredential> =
            arr?.items?.mapNotNull { (it as? JsonValue.Obj)?.let(::fromJson) } ?: emptyList()
    }
}

/**
 * The RP's self-declared registration data, carried in the OpenID4VP `verifier_info` `registrar_dataset`
 * element (ETSI TS 119 472-2 §6.3, REQ-RO-02). It is **self-declared**: only the request (WRPAC) signature
 * covers it, so it is NOT registrar-attested. The wallet uses it for display / the transaction log
 * (DASH_03) and — when no WRPRC is present — as the key into the registrar's TS5 API (`registryURI` +
 * `identifier`) to obtain the same information *registrar-signed*.
 */
class RegistrarDataset(
    /** The RP's unique identifier value (`identifier[0].identifier`, e.g. "HOPAE-DEMO-VERIFIER-LU-01") — the
     *  key for a TS5 registry lookup. Note: this is the raw value, without a semantic prefix. */
    val identifier: String?,
    val registryURI: String?,
    val policyURI: String?,
    val intendedUseIdentifier: String?,
    val srvDescription: List<RegistrationLocalizedText>,
    val purpose: List<RegistrationLocalizedText>,
    /** The credentials/claims the RP self-declares it is registered to request (REQ-RO-12). */
    val credentials: List<RegisteredCredential>,
    /** The raw dataset JSON, for the transaction log. */
    val raw: JsonValue.Obj,
) {
    companion object {
        private fun langTexts(arr: JsonValue.Arr?): List<RegistrationLocalizedText> =
            arr?.items?.mapNotNull { item ->
                val o = item as? JsonValue.Obj ?: return@mapNotNull null
                val lang = (o["lang"] as? JsonValue.Str)?.value ?: return@mapNotNull null
                // registrar_dataset uses `content`; WRPRC uses `value` — accept either.
                val text = (o["content"] as? JsonValue.Str)?.value ?: (o["value"] as? JsonValue.Str)?.value
                    ?: return@mapNotNull null
                RegistrationLocalizedText(lang, text)
            } ?: emptyList()

        fun fromData(data: JsonValue.Obj): RegistrarDataset {
            val identifier = ((data["identifier"] as? JsonValue.Arr)?.items?.firstOrNull() as? JsonValue.Obj)
                ?.let { (it["identifier"] as? JsonValue.Str)?.value }
            return RegistrarDataset(
                identifier = identifier,
                registryURI = (data["registryURI"] as? JsonValue.Str)?.value,
                policyURI = (data["policyURI"] as? JsonValue.Str)?.value,
                intendedUseIdentifier = (data["intendedUseIdentifier"] as? JsonValue.Str)?.value,
                srvDescription = langTexts(data["srvDescription"] as? JsonValue.Arr),
                purpose = langTexts(data["purpose"] as? JsonValue.Arr),
                credentials = RegisteredCredential.listFromJson(data["credential"] as? JsonValue.Arr),
                raw = data,
            )
        }
    }
}

/**
 * Attribute-scope check (ETSI TS 119 475 RPRC_21): the requested claim paths a Relying Party is **not**
 * registered to request. An empty result means every requested attribute is within the RP's registration.
 */
object RegistrationScope {
    /** Requested DCQL claim paths not covered by [registered]. Wildcard paths are skipped (indeterminate). */
    fun unregistered(dcql: DcqlQuery, registered: List<RegisteredCredential>): List<UnregisteredClaim> {
        if (registered.isEmpty()) return emptyList()
        val out = mutableListOf<UnregisteredClaim>()
        for (cq in dcql.credentials) {
            val matching = registered.filter { it.format == cq.format && metaMatches(cq.meta, it) }
            for (claim in cq.claims) {
                val path = concretePath(claim.path) ?: continue // skip wildcard/index-only paths
                if (matching.none { rc -> rc.claims.any { it == path } }) {
                    out.add(UnregisteredClaim(cq.id, cq.format, path))
                }
            }
        }
        return out
    }

    /** A DCQL path as plain strings, or null when it contains a wildcard (can't be pinned to a fixed path). */
    private fun concretePath(path: List<PathElement>): List<String>? =
        path.map {
            when (it) {
                is PathElement.Key -> it.name
                is PathElement.Index -> it.index.toString()
                PathElement.Wildcard -> return null
            }
        }

    private fun metaMatches(meta: CredentialMeta?, rc: RegisteredCredential): Boolean {
        if (meta == null) return true
        meta.doctypeValue?.let { if (it != rc.docType) return false }
        meta.vctValues?.let { req -> if (rc.vctValues == null || req.none { it in rc.vctValues }) return false }
        return true
    }
}

/** One requested attribute the RP is not registered to request (RPRC_21). */
data class UnregisteredClaim(
    val credentialQueryId: String,
    val format: String,
    val path: List<String>,
)
