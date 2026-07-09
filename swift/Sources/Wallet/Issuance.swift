import Foundation
import OpenID4VCI
import WalletAPI

/// The Transaction Code input hints from a Credential Offer (OpenID4VCI §4.1.1) — how to render the
/// code-entry screen. Guidance, not a wire constraint: `validate` returns any inconsistencies for the
/// host to warn about, but the SDK never rejects a code on their basis (a hint can be wrong; the issuer
/// is the authority).
public struct TxCodeSpec {
    private let raw: OpenID4VCI.CredentialOffer.TxCodeSpec
    init(_ raw: OpenID4VCI.CredentialOffer.TxCodeSpec) { self.raw = raw }

    /// Expected length, if advertised — for laying out the input field.
    public var length: Int? { raw.length }

    /// `numeric` (digits only) or `text` (any characters); nil means the §4.1.1 default, `numeric`.
    public var inputMode: String? { raw.inputMode }

    /// How the End-User obtains the code (≤300 chars); show it next to the input.
    public var description: String? { raw.description }

    /// The ways `code` departs from these hints (empty = consistent). Advisory — never blocks issuance.
    public func validate(_ code: String) -> [String] { raw.violations(code) }
}

/// A resolved credential offer (OpenID4VCI §4) — the first step of the 2-phase issuance flow.
public struct CredentialOffer {
    let raw: OpenID4VCI.CredentialOffer
    init(_ raw: OpenID4VCI.CredentialOffer) { self.raw = raw }

    public var credentialIssuer: String { raw.credentialIssuer }
    public var credentialConfigurationIds: [String] { raw.credentialConfigurationIds }
    public var requiresTxCode: Bool { raw.txCode != nil }

    /// The transaction-code input hints (§4.1.1), or nil when the offer needs no code.
    public var txCode: TxCodeSpec? { raw.txCode.map { TxCodeSpec($0) } }
}

/// What to issue: from an offer or wallet-initiated, plus key policy and (if pre-known) the tx_code.
public struct IssuanceRequest {
    enum Source {
        case fromOffer(CredentialOffer)
        case fromIssuer(String)
    }

    let source: Source
    let configurationId: String
    let txCode: String?
    let keySpec: KeySpec
    let policy: CredentialPolicy

    /// 2-phase flow: issue an offered credential (pre-authorized or authorization-code grant).
    public static func fromOffer(_ offer: CredentialOffer, configurationId: String, txCode: String? = nil,
                                 keySpec: KeySpec = KeySpec(), policy: CredentialPolicy = CredentialPolicy()) -> IssuanceRequest {
        IssuanceRequest(source: .fromOffer(offer), configurationId: configurationId, txCode: txCode, keySpec: keySpec, policy: policy)
    }

    /// Wallet-initiated issuance from an issuer (authorization-code grant, browser step required).
    public static func fromIssuer(_ credentialIssuer: String, configurationId: String,
                                  keySpec: KeySpec = KeySpec(), policy: CredentialPolicy = CredentialPolicy()) -> IssuanceRequest {
        IssuanceRequest(source: .fromIssuer(credentialIssuer), configurationId: configurationId, txCode: nil, keySpec: keySpec, policy: policy)
    }
}

/// Terminal issuance outcome (credentials stored; ids for follow-up).
public struct IssuanceResult { public let issued: [CredentialId] }

/// Issuance session state.
public enum IssuanceState {
    case preparing
    case authorizationRequired(String)
    /// The pre-authorized flow needs a transaction code; the associated value carries the §4.1.1 hints, if any.
    case txCodeRequired(TxCodeSpec?)
    case processing
    case completed(IssuanceResult)
    case failed(IssuanceError)

    public var isTerminal: Bool {
        switch self {
        case .completed, .failed: return true
        default: return false
        }
    }
}
