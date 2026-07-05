package com.hopae.eudi.wallet

import com.hopae.eudi.wallet.sdjwt.JsonValue
import com.hopae.eudi.wallet.spi.CredentialId
import com.hopae.eudi.wallet.store.CredentialStore
import com.hopae.eudi.wallet.store.CredentialStoreChange
import com.hopae.eudi.wallet.vp.DcqlEngine
import com.hopae.eudi.wallet.vp.DcqlQuery
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map

/** Stored-credential management (API-CONTRACT.md §6.5). Reads are local; `status` hits the network. */
class CredentialsService internal constructor(private val store: CredentialStore) {

    suspend fun list(filter: CredentialFilter = CredentialFilter.All): List<Credential> =
        store.list().map { it.toCredential() }.filter { filter.matches(it) }

    suspend fun get(id: CredentialId): Credential? = store.get(id)?.toCredential()

    suspend fun delete(id: CredentialId) = store.delete(id)

    /** Reactive list changes (Added/Updated/Removed) for UI refresh. */
    val changes: Flow<CredentialChange> = store.changes.map { it.toCredentialChange() }

    /**
     * Matches stored credentials against a DCQL query (OpenID4VP §6) — presentation-independent.
     * Uses the same engine the presentation flow uses (credential_sets, claim_sets, null-wildcard).
     */
    suspend fun match(dcqlJson: String): CredentialMatch {
        val envelopes = store.list()
        val held = envelopes.mapNotNull { it.toQueryable() }
        val query = DcqlQuery.parse(JsonValue.parse(dcqlJson) as JsonValue.Obj)
        val result = DcqlEngine.match(query, held)
        val byId = envelopes.associateBy { it.id.value }
        return CredentialMatch(
            satisfiable = result.isSatisfiable(),
            byQuery = result.candidatesByQuery.mapValues { (_, candidates) ->
                candidates.mapNotNull { candidate ->
                    byId[candidate.credential.credentialId]?.let { MatchedCredential(it.toCredential(), candidate.disclosedPaths) }
                }
            },
        )
    }
}

/** Result of [CredentialsService.match]: which held credentials satisfy each query, and disclosed paths. */
class CredentialMatch(
    val satisfiable: Boolean,
    val byQuery: Map<String, List<MatchedCredential>>,
)

class MatchedCredential(val credential: Credential, val disclosedPaths: List<List<String>>)

sealed interface CredentialChange {
    val id: CredentialId

    data class Added(override val id: CredentialId) : CredentialChange
    data class Updated(override val id: CredentialId) : CredentialChange
    data class Removed(override val id: CredentialId) : CredentialChange
}

internal fun CredentialStoreChange.toCredentialChange(): CredentialChange = when (this) {
    is CredentialStoreChange.Added -> CredentialChange.Added(id)
    is CredentialStoreChange.Updated -> CredentialChange.Updated(id)
    is CredentialStoreChange.Removed -> CredentialChange.Removed(id)
}
