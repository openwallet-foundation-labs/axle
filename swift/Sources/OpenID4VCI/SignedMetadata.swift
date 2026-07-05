import Foundation
import SdJwt

/// Verifies the issuer's `signed_metadata` JWT (OpenID4VCI §11.2.3) and returns its verified claims.
/// The adapter (app-supplied) checks the JWS signature and its x5c chain to a trust anchor — keeping
/// OpenID4VCI decoupled from the trust module (ports & adapters).
public protocol SignedMetadataVerifier: Sendable {
    func verify(signedMetadataJws: String) async throws -> JsonValue
}

/// How to treat the issuer's `signed_metadata` (OpenID4VCI §11.2.3).
public enum IssuerMetadataPolicy {
    /// Ignore `signed_metadata`; use the fetched JSON as-is (default).
    case ignoreSigned
    /// Verify and prefer `signed_metadata` when present; fall back to the fetched JSON otherwise.
    case preferSigned(any SignedMetadataVerifier)
    /// Require verified `signed_metadata`; fail if it is absent or its verification fails.
    case requireSigned(any SignedMetadataVerifier)
}

/// Overlays verified signed-metadata claims onto the fetched JSON (verified wins); drops `signed_metadata`.
func mergeSignedMetadata(plain: JsonValue, verified: JsonValue) -> JsonValue {
    guard case let .obj(p) = plain, case let .obj(v) = verified else { return plain }
    var order: [String] = []
    var seen = Set<String>()
    for (k, _) in p where k != "signed_metadata" && seen.insert(k).inserted { order.append(k) }
    for (k, _) in v where k != "signed_metadata" && seen.insert(k).inserted { order.append(k) }
    var vmap: [String: JsonValue] = [:]
    for (k, val) in v where vmap[k] == nil { vmap[k] = val }
    var pmap: [String: JsonValue] = [:]
    for (k, val) in p where pmap[k] == nil { pmap[k] = val }
    return .obj(order.map { ($0, vmap[$0] ?? pmap[$0]!) })
}
