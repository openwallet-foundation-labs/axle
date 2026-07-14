import CredentialStore
import MDoc
import OpenID4VP
import SdJwt
import WalletAPI

extension CredentialEnvelope {
    /// Parses the payload into the disclosed claims tree — no signer needed. Degrades to nil on corruption.
    /// Payload convention: SD-JWT VC = compact string bytes; mdoc = IssuerSigned CBOR.
    func claimsTree() -> JsonValue? {
        guard case let .issued(_, instances) = lifecycle, let payload = instances.first?.payload else { return nil }
        do {
            switch format {
            case .sdJwtVc:
                return try SdJwtHolder.processedClaims(SdJwt.parse(String(decoding: payload, as: UTF8.self)))
            case .msoMdoc:
                return try HeldMdoc(credentialId: id.value, issuerSigned: IssuerSigned.decode(payload)).claims
            }
        } catch {
            return nil
        }
    }

    /// A stored credential exposed to the DCQL engine (read-only; presentation adds a signer in Phase C).
    func toQueryable() -> QueryableCredential? {
        guard let claims = claimsTree() else { return nil }
        switch format {
        case let .sdJwtVc(vct):
            return StoredQueryable(credentialId: id.value, format: "dc+sd-jwt", vct: vct, docType: nil, claims: claims)
        case let .msoMdoc(docType):
            return StoredQueryable(credentialId: id.value, format: "mso_mdoc", vct: nil, docType: docType, claims: claims)
        }
    }

    /// Assembles the format-agnostic `Credential` view (with parsed claims) from a storage envelope.
    func toCredential() -> Credential {
        let lc: Lifecycle
        switch lifecycle {
        case let .issued(policy, instances):
            lc = .issued(claims: claimsTree().map { flattenClaims($0, format: format) } ?? [], validity: nil,
                         instances: CredentialInstances(remaining: instances.count, use: policy.use))
        case let .deferred(_, retryAfter):
            lc = .deferred(retryAfter: retryAfter)
        case let .pending(authorizationUrl, _):
            lc = .pending(authorizationUrl: authorizationUrl)
        }
        return Credential(
            id: id, format: format, lifecycle: lc,
            issuer: metadata.map { IssuerInfo(url: $0.issuerUrl, displayName: $0.issuerDisplayName, trusted: $0.issuerTrusted, registered: $0.issuerRegistered) },
            display: metadata.map { CredentialDisplay(name: $0.displayName, logoUri: $0.logoUri, backgroundColor: $0.backgroundColor) },
            configurationId: metadata?.configurationId, createdAt: createdAt)
    }
}

struct StoredQueryable: QueryableCredential {
    let credentialId: String
    let format: String
    let vct: String?
    let docType: String?
    let claims: JsonValue
}

/// Flattens a claims tree into path-addressed leaf claims (nested objects → deeper paths), classifying each.
func flattenClaims(_ value: JsonValue, format: CredentialFormat, prefix: [String] = []) -> [Claim] {
    guard case let .obj(entries) = value else { return [] }
    return entries.flatMap { key, child -> [Claim] in
        let path = prefix + [key]
        if case .obj = child { return flattenClaims(child, format: format, prefix: path) }
        return [Claim(path: path, value: ClaimValue(json: child, kind: kindOf(child, key)), category: categoryOf(format, path))]
    }
}

/// SD-JWT VC registered / JWT claims that carry credential metadata rather than subject data.
private let jwtRegistered: Set<String> = ["iss", "sub", "aud", "exp", "nbf", "iat", "jti", "cnf", "vct", "status"]

/// ARF/ISO administrative element names (both formats) — issuance/validity, issuing party, document identity.
private let adminElements: Set<String> = [
    "issue_date", "issuance_date", "date_of_issuance", "expiry_date", "expiration_date", "valid_from", "valid_until",
    "issuing_authority", "issuing_country", "issuing_jurisdiction",
    "document_number", "administrative_number", "un_distinguishing_sign", "portrait_capture_date", "version",
]

private func categoryOf(_ format: CredentialFormat, _ path: [String]) -> ClaimCategory {
    // SD-JWT VC: anything under a top-level registered claim (checked on the ROOT key, so nested children of
    // object claims like cnf/status are classified too) is metadata.
    if case .sdJwtVc = format, let first = path.first, jwtRegistered.contains(first.lowercased()) { return .metadata }
    if let last = path.last, adminElements.contains(last.lowercased()) { return .metadata }
    return .subject
}

private func kindOf(_ json: JsonValue, _ key: String) -> ClaimValueKind {
    switch json {
    case .bool: return .boolean
    case .numInt, .numDouble: return .number
    case .arr: return .array
    case let .str(s): return (s.range(of: "^\\d{4}-\\d{2}-\\d{2}", options: .regularExpression) != nil || key.hasSuffix("_date")) ? .date : .text
    case .null: return .unknown
    default: return .text
    }
}
