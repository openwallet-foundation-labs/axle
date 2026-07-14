import Foundation
import SdJwt
import WalletAPI

/// Format-agnostic credential view, assembled from the storage envelope.
public struct Credential {
    public let id: CredentialId
    public let format: CredentialFormat
    public let lifecycle: Lifecycle
    public let issuer: IssuerInfo?
    public let display: CredentialDisplay?
    public let configurationId: String?
    public let createdAt: Date
}

/// Where the credential came from (captured from issuer metadata at issuance).
public struct IssuerInfo {
    public let url: String
    public let displayName: String?
    /// The credential's issuer signature (DSC) chained to a trusted issuer anchor: true/false/nil(unchecked).
    public let trusted: Bool?
    /// The issuer's `.well-known` signed metadata chained to a trusted issuer anchor (a registered issuer).
    public let registered: Bool?
    public init(url: String, displayName: String?, trusted: Bool? = nil, registered: Bool? = nil) {
        self.url = url; self.displayName = displayName; self.trusted = trusted; self.registered = registered
    }
}

/// Display metadata for a credential type (issuer-metadata derived).
public struct CredentialDisplay {
    public let name: String?
    public let logoUri: String?
    public let backgroundColor: String?
}

public enum Lifecycle {
    case issued(claims: [Claim], validity: ValidityInfo?, instances: CredentialInstances)
    case deferred(retryAfter: Date?)
    case pending(authorizationUrl: String?)
}

/// A disclosed claim, path-addressed (namespace+element for mdoc, JSON path for SD-JWT VC).
public struct Claim {
    public let path: [String]
    public let value: ClaimValue
    public let category: ClaimCategory
    public init(path: [String], value: ClaimValue, category: ClaimCategory = .subject) {
        self.path = path; self.value = value; self.category = category
    }
}

/// Whether a claim carries the subject's personal data or the credential's administrative metadata. Derived
/// structurally where possible (SD-JWT VC registered claims like iss/iat/exp/vct/cnf/status) and from the
/// ARF/ISO administrative element names otherwise. A hint for grouping — consumers may present it as they like.
public enum ClaimCategory { case subject, metadata }

/// The value's underlying shape, so a UI can render it without re-sniffing the raw type.
public enum ClaimValueKind { case text, number, boolean, date, array, unknown }

/// A claim value with a format-agnostic rendering and a `kind` hint.
public struct ClaimValue {
    let json: JsonValue // internal — not exposed in the public signature
    public let kind: ClaimValueKind
    init(json: JsonValue, kind: ClaimValueKind = .text) { self.json = json; self.kind = kind }
    public func display() -> String {
        switch json {
        case let .str(s): return s
        case let .numInt(n): return String(n)
        case let .numDouble(d): return String(d)
        case let .bool(b): return b ? "Yes" : "No"
        case let .arr(items): return items.map { scalar($0) }.joined(separator: ", ")
        case .null: return ""
        default: return json.serialize()
        }
    }
    private func scalar(_ v: JsonValue) -> String {
        switch v {
        case let .str(s): return s
        case let .numInt(n): return String(n)
        case let .numDouble(d): return String(d)
        case let .bool(b): return b ? "Yes" : "No"
        default: return v.serialize()
        }
    }
}

public struct ValidityInfo { public let validFrom: Date?; public let validUntil: Date? }

/// Batch instance accounting (HAIP one-time-use / rotate).
public struct CredentialInstances { public let remaining: Int; public let use: KeyUse }
