package com.hopae.eudi.wallet.vp

import com.hopae.eudi.wallet.sdjwt.JsonValue

/** A credential the wallet holds, in a shape DCQL can match against. */
interface QueryableCredential {
    /** Wallet-local identifier of this stored credential. */
    val credentialId: String
    val format: String
    val vct: String?
    val docType: String?

    /** Processed claim tree (SD-JWT VC: disclosed + always-visible claims). */
    val claims: JsonValue.Obj
}

/** One held credential that satisfies a credential query, plus the concrete claim paths to disclose. */
class CandidateMatch(
    val query: CredentialQuery,
    val credential: QueryableCredential,
    val disclosedPaths: List<List<String>>,
)

class DcqlMatchResult(
    val candidatesByQuery: Map<String, List<CandidateMatch>>,
    val credentialSets: List<CredentialSetQuery>?,
) {
    /** Query ids the response must answer (from credential_sets, or all when absent). */
    val requiredQueryIds: Set<String> by lazy {
        if (credentialSets == null) candidatesByQuery.keys
        else credentialSets.filter { it.required }.flatMap { it.options.flatten() }.toSet()
            .ifEmpty { candidatesByQuery.keys }
    }

    /** Whether every required credential_set has an option whose queries all have a candidate. */
    fun isSatisfiable(): Boolean {
        val answerable = candidatesByQuery.filterValues { it.isNotEmpty() }.keys
        val sets = credentialSets
        if (sets == null) return candidatesByQuery.keys.all { it in answerable }
        return sets.filter { it.required }.all { set ->
            set.options.any { option -> option.all { it in answerable } }
        }
    }
}

/** DCQL matching engine (OpenID4VP §6). Pure logic — no I/O. */
object DcqlEngine {

    fun match(query: DcqlQuery, held: List<QueryableCredential>): DcqlMatchResult {
        val byQuery = query.credentials.associate { cq ->
            cq.id to held.mapNotNull { matchCredential(cq, it) }
        }
        return DcqlMatchResult(byQuery, query.credentialSets)
    }

    /** Returns a candidate if [credential] satisfies [cq], else null. */
    fun matchCredential(cq: CredentialQuery, credential: QueryableCredential): CandidateMatch? {
        if (credential.format != cq.format) return null
        cq.meta?.let { meta ->
            meta.vctValues?.let { if (credential.vct == null || credential.vct !in it) return null }
            meta.doctypeValue?.let { if (credential.docType != it) return null }
        }

        // Determine the set of claims that must be satisfied.
        val claimsToUse: List<ClaimQuery> = when {
            cq.claims.isEmpty() -> emptyList() // request the whole credential (no per-claim constraint)
            cq.claimSets == null -> cq.claims
            else -> {
                val byId = cq.claims.filter { it.id != null }.associateBy { it.id }
                // first claim_set whose every claim is satisfiable
                val chosen = cq.claimSets.firstOrNull { set ->
                    set.all { id -> byId[id]?.let { satisfies(credential, it).first } ?: false }
                } ?: return null
                chosen.mapNotNull { byId[it] }
            }
        }

        val disclosed = mutableListOf<List<String>>()
        for (claim in claimsToUse) {
            val (ok, paths) = satisfies(credential, claim)
            if (!ok) return null
            disclosed.addAll(paths)
        }
        return CandidateMatch(cq, credential, disclosed.distinct())
    }

    /** True if [claim] is present (and value-matches) in [credential]; returns the concrete leaf paths. */
    private fun satisfies(credential: QueryableCredential, claim: ClaimQuery): Pair<Boolean, List<List<String>>> {
        val resolved = resolvePath(credential.claims, claim.path, emptyList())
        if (resolved.isEmpty()) return false to emptyList()
        val values = claim.values
        if (values == null) return true to resolved.map { it.first }
        // values present: keep leaves whose value matches one of the allowed values
        val matching = resolved.filter { (_, v) -> values.any { valueEquals(it, v) } }
        return if (matching.isEmpty()) false to emptyList() else true to matching.map { it.first }
    }

    /**
     * Resolves a DCQL claims path against a JSON tree, returning (concrete-path, value) leaves.
     * Wildcard elements fan out over array members (array indices become string path segments).
     */
    fun resolvePath(node: JsonValue, path: List<PathElement>, prefix: List<String>): List<Pair<List<String>, JsonValue>> {
        if (path.isEmpty()) return listOf(prefix to node)
        val head = path.first()
        val tail = path.drop(1)
        return when (head) {
            is PathElement.Key -> {
                val obj = node as? JsonValue.Obj ?: return emptyList()
                val v = obj[head.name] ?: return emptyList()
                resolvePath(v, tail, prefix + head.name)
            }
            is PathElement.Index -> {
                val arr = node as? JsonValue.Arr ?: return emptyList()
                val v = arr.items.getOrNull(head.index) ?: return emptyList()
                resolvePath(v, tail, prefix + head.index.toString())
            }
            PathElement.Wildcard -> {
                val arr = node as? JsonValue.Arr ?: return emptyList()
                arr.items.flatMapIndexed { i, v -> resolvePath(v, tail, prefix + i.toString()) }
            }
        }
    }

    private fun valueEquals(a: JsonValue, b: JsonValue): Boolean = a == b
}
