package com.hopae.eudi.wallet

import com.hopae.eudi.wallet.spi.CredentialId
import com.hopae.eudi.wallet.vp.DcqlMatchResult
import com.hopae.eudi.wallet.vp.ResolvedRequest

/**
 * A resolved verifier request, ready for the consent screen: who is asking, what they want, and which
 * stored credentials can satisfy each query. The raw resolved request + match are carried for [respond].
 */
class PresentationRequest internal constructor(
    val verifier: VerifierInfo,
    val queries: List<QueryPresentation>,
    val transactionData: List<String>?,
    val satisfiable: Boolean,
    internal val resolved: ResolvedRequest,
    internal val matches: DcqlMatchResult,
)

/** Who is requesting, and whether trust was established (signed request verified to a reader anchor). */
class VerifierInfo(
    val clientId: String,
    val clientIdScheme: String,
    val commonName: String?,
    val trusted: Boolean,
    /**
     * The relying party's registrar-issued registration (WRPRC), when one accompanied the request and
     * validated. Surfaces the declared purpose / entitlements / intermediary for the consent screen.
     */
    val registration: VerifierRegistration? = null,
)

/** A localized string (BCP-47 `lang` + `value`) from a WRPRC `purpose`. */
data class PurposeText(val lang: String, val value: String)

/** The relying party's registration (ETSI TS 119 475 WRPRC), validated and bound to the request's WRPAC. */
class VerifierRegistration(
    /**
     * `sub` — the registered semantic identifier (bound to the WRPAC organizationIdentifier). For an
     * intermediated request this is the **final** relying party, never the intermediary.
     */
    val subject: String,
    /** EU-level entitlements/roles asserted for the relying party (>=1). */
    val entitlements: List<String>,
    /** The declared intended-use, for display on the consent screen. */
    val purpose: List<PurposeText>,
    /** When the RP operates through an intermediary: its identifier and user-facing name. */
    val intermediarySub: String?,
    val intermediaryName: String?,
    /**
     * Token Status List result: true = valid, false = revoked/suspended, null = not checked. A revoked WRPRC
     * is refused before the consent screen, so a surfaced registration is always valid or unchecked.
     */
    val statusValid: Boolean?,
    /**
     * True iff a registrar-issued WRPRC attested this registration (authoritative, registrar-sealed). False
     * when only the RP's self-declared `registrar_dataset` backs it (no WRPRC) — treat those fields as
     * unverified unless a registrar TS5 lookup confirmed them.
     */
    val attested: Boolean = false,
    /** The RP's registry base URI (`registrar_dataset.registryURI`), for the transaction log / TS5 lookup. */
    val registryURI: String? = null,
    /** The RP's privacy-policy URL (`registrar_dataset.policyURI`), for the consent screen. */
    val policyURI: String? = null,
    /**
     * Attribute-scope check (ETSI TS 119 475 RPRC_21): the requested claim paths the RP is **not** registered
     * to request. Empty = every requested attribute is within the registration; surfaced to the User so an
     * over-asking verifier is visible at approval. Each entry is the claim path as string segments.
     */
    val unregisteredClaims: List<List<String>> = emptyList(),
)

/** One DCQL query with the stored credentials that can answer it. */
class QueryPresentation(
    val queryId: String,
    val required: Boolean,
    val candidates: List<PresentationCandidate>,
    /** §6.1 `multiple`: whether the verifier accepts more than one credential for this query. */
    val multiple: Boolean = false,
)

/** A stored credential that satisfies a query, with the claim paths it would disclose. */
class PresentationCandidate(
    val credentialId: CredentialId,
    val disclosedPaths: List<List<String>>,
)

/**
 * The user's choice of which credential(s) answer each query. A `multiple: false` query takes exactly one
 * credential; a `multiple: true` query (§6.1) may take several.
 */
class PresentationSelection(val chosen: Map<String, List<CredentialId>>) {
    companion object {
        /** Auto-pick: all candidates for a `multiple` query, else the first candidate, for every required query. */
        fun auto(request: PresentationRequest): PresentationSelection =
            PresentationSelection(
                request.queries.filter { it.required && it.candidates.isNotEmpty() }
                    .associate { q ->
                        q.queryId to if (q.multiple) q.candidates.map { it.credentialId }
                        else listOf(q.candidates.first().credentialId)
                    },
            )
    }
}

/** Presentation session state. */
sealed interface PresentationState {
    data object ResolvingRequest : PresentationState
    data class RequestResolved(val request: PresentationRequest) : PresentationState
    data object Submitting : PresentationState

    /**
     * Success. [redirectUri] is the verifier redirect for the remote (URL/QR) flow; [dcApiResponse] is
     * the JSON object to hand back to the platform for the Digital Credentials API flow. Exactly one is set.
     */
    data class Completed(val redirectUri: String?, val dcApiResponse: String? = null) : PresentationState

    /**
     * The user refused. For the remote flow the wallet has told the verifier (`access_denied`, §8.5);
     * [redirectUri] is the URI the verifier asked the wallet to send the user agent to, if any.
     */
    data class Declined(val redirectUri: String? = null) : PresentationState
    data class Failed(val error: WalletError.Presentation) : PresentationState

    val isTerminal: Boolean get() = this is Completed || this is Declined || this is Failed
}
