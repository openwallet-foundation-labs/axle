import Foundation

/// Typed OpenID4VCI errors. `oauthError` preserves the server's RFC 6749/OpenID4VCI
/// error code verbatim (e.g. "invalid_grant") for diagnostics and caller handling.
public enum VciError: Error, CustomStringConvertible {
    case invalidOffer(String)
    case metadata(String)
    case http(status: Int, endpoint: String, body: String?)
    case oauth(error: String, description: String?, endpoint: String)
    case protocolError(String)
    case txCodeRequired(length: Int?, inputMode: String?)

    public var description: String {
        switch self {
        case let .invalidOffer(m): return "invalid credential offer: \(m)"
        case let .metadata(m): return "metadata error: \(m)"
        case let .http(status, endpoint, body):
            return "HTTP \(status) from \(endpoint)" + (body.map { ": \($0)" } ?? "")
        case let .oauth(error, desc, endpoint):
            return "OAuth error '\(error)' from \(endpoint)" + (desc.map { ": \($0)" } ?? "")
        case let .protocolError(m): return "protocol error: \(m)"
        case let .txCodeRequired(length, mode):
            return "transaction code required (length=\(String(describing: length)), mode=\(String(describing: mode)))"
        }
    }
}
