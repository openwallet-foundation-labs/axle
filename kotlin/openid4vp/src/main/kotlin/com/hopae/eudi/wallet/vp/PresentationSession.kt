package com.hopae.eudi.wallet.vp

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/** Per-query consent data: which held credentials can answer it and what each would disclose. */
class QueryPresentation(
    val queryId: String,
    val required: Boolean,
    val candidates: List<CandidateMatch>,
)

/** Everything the app needs to render the consent screen — immutable, not a UI model. */
class PresentationRequest(
    val verifier: VerifierInfo,
    val queries: List<QueryPresentation>,
    val transactionData: List<String>?,
    val satisfiable: Boolean,
)

sealed interface PresentationState {
    data object ResolvingRequest : PresentationState
    data class RequestResolved(val request: PresentationRequest) : PresentationState
    data object Submitting : PresentationState
    data class Completed(val redirectUri: String?) : PresentationState
    data object Declined : PresentationState
    data class Failed(val error: VpException) : PresentationState
}

/**
 * Drives a single OpenID4VP remote presentation (API-CONTRACT §6.3). One-shot: start resolves
 * and matches; [respond] builds and submits; the flow ends in Completed/Declined/Failed.
 */
class PresentationSession internal constructor(
    private val client: Openid4VpClient,
    private val held: List<HeldSdJwtVc>,
) {
    private val _state = MutableStateFlow<PresentationState>(PresentationState.ResolvingRequest)
    val state: StateFlow<PresentationState> = _state.asStateFlow()

    private var resolved: ResolvedRequest? = null
    private var matches: DcqlMatchResult? = null

    suspend fun start(requestUri: String) {
        try {
            val request = client.resolveRequest(requestUri)
            val m = client.match(request, held)
            resolved = request
            matches = m
            val queries = request.dcqlQuery.credentials.map { cq ->
                QueryPresentation(cq.id, cq.id in m.requiredQueryIds, m.candidatesByQuery[cq.id].orEmpty())
            }
            _state.value = PresentationState.RequestResolved(
                PresentationRequest(request.verifier, queries, request.transactionData, m.isSatisfiable())
            )
        } catch (e: VpException) {
            _state.value = PresentationState.Failed(e)
        }
    }

    suspend fun respond(selection: PresentationSelection) {
        val request = resolved ?: error("session not resolved")
        val m = matches ?: error("session not resolved")
        _state.value = PresentationState.Submitting
        try {
            val result = client.respond(request, m, selection, held)
            _state.value = PresentationState.Completed(result.redirectUri)
        } catch (e: VpException) {
            _state.value = PresentationState.Failed(e)
        }
    }

    fun decline() {
        _state.value = PresentationState.Declined
    }
}
