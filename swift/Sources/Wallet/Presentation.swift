import Foundation
import OpenID4VP
import WalletAPI

/// A resolved verifier request, ready for the consent screen: who is asking, what they want, and which
/// stored credentials can satisfy each query. The raw resolved request + match are carried for respond.
public struct PresentationRequest {
    public let verifier: VerifierInfo
    public let queries: [QueryPresentation]
    public let transactionData: [String]?
    public let satisfiable: Bool
    let resolved: ResolvedRequest
    let matches: DcqlMatchResult
}

/// Who is requesting, and whether trust was established (signed request verified to a reader anchor).
public struct VerifierInfo {
    public let clientId: String
    public let clientIdScheme: String
    public let commonName: String?
    public let trusted: Bool
    /// The relying party's registrar-issued registration (WRPRC), when one accompanied the request and
    /// validated. Surfaces the declared purpose / entitlements / intermediary for the consent screen.
    public let registration: VerifierRegistration?
}

/// A localized string (BCP-47 `lang` + `value`) from a WRPRC `purpose`.
public struct PurposeText: Equatable {
    public let lang: String
    public let value: String
    public init(lang: String, value: String) {
        self.lang = lang
        self.value = value
    }
}

/// The relying party's registration (ETSI TS 119 475 WRPRC), validated and bound to the request's WRPAC.
public struct VerifierRegistration {
    /// `sub` — the registered semantic identifier (bound to the WRPAC organizationIdentifier). For an
    /// intermediated request this is the **final** relying party, never the intermediary.
    public let subject: String
    /// EU-level entitlements/roles asserted for the relying party (≥1).
    public let entitlements: [String]
    /// The declared intended-use, for display on the consent screen.
    public let purpose: [PurposeText]
    /// When the RP operates through an intermediary: its identifier and user-facing name.
    public let intermediarySub: String?
    public let intermediaryName: String?
    /// Token Status List result: true = valid, false = revoked/suspended, nil = not checked. A revoked WRPRC
    /// is refused before the consent screen, so a surfaced registration is always valid or unchecked.
    public let statusValid: Bool?
    /// True iff a registrar-issued WRPRC attested this registration (authoritative, registrar-sealed, verified
    /// offline). False when only the RP's self-declared `registrar_dataset` backs it (no WRPRC).
    public let attested: Bool
    /// True iff the registration is registrar-verified — either WRPRC-attested (`attested`) OR confirmed
    /// online against the registrar's TS5 API (RPRC_16/18) for a dataset-only request. When false, the
    /// surfaced registration fields are only the RP's self-declaration.
    public let registrarVerified: Bool
    /// The RP's registry base URI (`registrar_dataset.registryURI`), for the transaction log / TS5 lookup.
    public let registryURI: String?
    /// The RP's privacy-policy URL (`registrar_dataset.policyURI`), for the consent screen.
    public let policyURI: String?
    /// Attribute-scope check (ETSI TS 119 475 RPRC_21): the requested claim paths the RP is **not** registered
    /// to request. Empty = every requested attribute is within the registration; surfaced to the User so an
    /// over-asking verifier is visible at approval. Each entry is the claim path as string segments.
    public let unregisteredClaims: [[String]]

    public init(subject: String, entitlements: [String], purpose: [PurposeText],
                intermediarySub: String?, intermediaryName: String?, statusValid: Bool?,
                attested: Bool = false, registrarVerified: Bool = false, registryURI: String? = nil,
                policyURI: String? = nil, unregisteredClaims: [[String]] = []) {
        self.subject = subject
        self.entitlements = entitlements
        self.purpose = purpose
        self.intermediarySub = intermediarySub
        self.intermediaryName = intermediaryName
        self.statusValid = statusValid
        self.attested = attested
        self.registrarVerified = registrarVerified
        self.registryURI = registryURI
        self.policyURI = policyURI
        self.unregisteredClaims = unregisteredClaims
    }
}

/// One DCQL query with the stored credentials that can answer it.
public struct QueryPresentation {
    public let queryId: String
    public let required: Bool
    public let candidates: [PresentationCandidate]
    /// §6.1 `multiple`: whether the verifier accepts more than one credential for this query.
    public let multiple: Bool

    public init(queryId: String, required: Bool, candidates: [PresentationCandidate], multiple: Bool = false) {
        self.queryId = queryId; self.required = required; self.candidates = candidates; self.multiple = multiple
    }
}

/// A stored credential that satisfies a query, with the claim paths it would disclose.
public struct PresentationCandidate {
    public let credentialId: CredentialId
    public let disclosedPaths: [[String]]
}

/// The user's choice of which credential(s) answer each query. A `multiple: false` query takes exactly one
/// credential; a `multiple: true` query (§6.1) may take several.
public struct PresentationSelection {
    public let chosen: [String: [CredentialId]]
    public init(chosen: [String: [CredentialId]]) { self.chosen = chosen }

    /// Auto-pick: all candidates for a `multiple` query, else the first candidate, for every required query.
    public static func auto(_ request: PresentationRequest) -> PresentationSelection {
        var chosen: [String: [CredentialId]] = [:]
        for query in request.queries where query.required && !query.candidates.isEmpty {
            chosen[query.queryId] = query.multiple ? query.candidates.map { $0.credentialId } : [query.candidates[0].credentialId]
        }
        return PresentationSelection(chosen: chosen)
    }
}

/// Presentation session state.
public enum PresentationState {
    case resolvingRequest
    case requestResolved(PresentationRequest)
    case submitting
    /// Success. `redirectUri` is the verifier redirect for the remote (URL/QR) flow; `dcApiResponse` is
    /// the JSON object to hand back to the platform for the Digital Credentials API flow. Exactly one is set.
    case completed(redirectUri: String?, dcApiResponse: String?)
    /// The user refused. For the remote flow the wallet has told the verifier (`access_denied`, §8.5);
    /// `redirectUri` is the URI the verifier asked the wallet to send the user agent to, if any.
    case declined(redirectUri: String?)
    case failed(PresentationError)

    public var isTerminal: Bool {
        switch self {
        case .completed, .declined, .failed: return true
        default: return false
        }
    }
}
