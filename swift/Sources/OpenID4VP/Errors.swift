import Foundation

/// Typed OpenID4VP errors.
public enum VpError: Error, CustomStringConvertible {
    case invalidRequest(String)
    case verifierNotTrusted(String)
    case queryNotSatisfiable(missing: Set<String>)
    case selectionIncomplete(String)
    case responseFailed(String)
    case unsupported(String)

    public var description: String {
        switch self {
        case let .invalidRequest(m): return "invalid request: \(m)"
        case let .verifierNotTrusted(m): return "verifier not trusted: \(m)"
        case let .queryNotSatisfiable(missing): return "DCQL query not satisfiable; missing: \(missing)"
        case let .selectionIncomplete(m): return "selection incomplete: \(m)"
        case let .responseFailed(m): return "response failed: \(m)"
        case let .unsupported(m): return "unsupported: \(m)"
        }
    }

    /// The §8.5 code that best describes this failure. Deliberately conservative: everything the wallet
    /// refuses to answer maps to `access_denied` (which reveals nothing about what it holds), and every
    /// malformed request to `invalid_request`.
    public var errorCode: VpErrorCode {
        switch self {
        case .invalidRequest, .unsupported, .responseFailed: return .invalidRequest
        case .verifierNotTrusted, .queryNotSatisfiable, .selectionIncomplete: return .accessDenied
        }
    }
}

/// The `error` values of an OpenID4VP Authorization Error Response (§8.5) — the RFC 6749 codes this
/// specification clarifies, plus the ones it adds. Sent to the verifier's `response_uri` by
/// `Openid4VpClient.reportError`.
public enum VpErrorCode: String, Sendable {
    /// Requested scope value is invalid, unknown, or malformed.
    case invalidScope = "invalid_scope"
    /// Malformed request: conflicting/absent DCQL, an unsupported Client Identifier Prefix, prefix rules violated.
    case invalidRequest = "invalid_request"
    /// `client_metadata` conflicts with metadata the wallet already knows for this Client Identifier.
    case invalidClient = "invalid_client"
    /// No credentials to satisfy the request, the user refused, or end-user authentication failed.
    case accessDenied = "access_denied"
    /// The wallet supports none of the formats the verifier requested.
    case vpFormatsNotSupported = "vp_formats_not_supported"
    /// `request_uri_method` was neither `get` nor `post` (case-sensitive).
    case invalidRequestUriMethod = "invalid_request_uri_method"
    /// A `transaction_data` entry is of an unknown type, malformed, or references credentials the wallet lacks.
    case invalidTransactionData = "invalid_transaction_data"
    /// The wallet could not be invoked and another component answered on its behalf.
    case walletUnavailable = "wallet_unavailable"

    public var code: String { rawValue }
}
