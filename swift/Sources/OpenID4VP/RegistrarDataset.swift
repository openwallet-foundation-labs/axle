import Foundation
import SdJwt

/// A credential (+ its claim paths) a Relying Party is registered to request — parsed from a WRPRC
/// `credentials` entry, a `registrar_dataset` `credential` entry, or a TS5 registry record. It captures
/// exactly what the RP is *allowed* to ask for, so the wallet can run the attribute-scope check
/// (ETSI TS 119 475 RPRC_21): every attribute a presentation requests must be covered by one of these.
public struct RegisteredCredential: Equatable, Sendable {
    public let format: String
    /// mdoc doctype (`meta.doctype_value`), when `format` is `mso_mdoc`.
    public let docType: String?
    /// SD-JWT VC types (`meta.vct_values`), when `format` is `dc+sd-jwt`.
    public let vctValues: [String]?
    /// Each registered claim path as string segments, e.g. `["org.iso.18013.5.1","given_name"]`.
    public let claims: [[String]]

    public init(format: String, docType: String?, vctValues: [String]?, claims: [[String]]) {
        self.format = format
        self.docType = docType
        self.vctValues = vctValues
        self.claims = claims
    }

    /// Parses one `{ format, meta, claim | claims: [{ path: [...] }] }` object; nil if unusable.
    public static func fromJson(_ o: JsonValue) -> RegisteredCredential? {
        guard case let .str(format)? = o["format"] else { return nil }
        var docType: String?
        var vctValues: [String]?
        if let meta = o["meta"] {
            if case let .str(d)? = meta["doctype_value"] { docType = d }
            if case let .arr(items)? = meta["vct_values"] {
                vctValues = items.compactMap { if case let .str(s) = $0 { return s } else { return nil } }
            }
        }
        // The registrar emits the claim list as `claim`; some producers use `claims`. Accept either.
        var claimArr: [JsonValue] = []
        if case let .arr(a)? = o["claim"] { claimArr = a } else if case let .arr(a)? = o["claims"] { claimArr = a }
        let claims: [[String]] = claimArr.compactMap { c in
            guard case let .arr(pathArr)? = c["path"] else { return nil }
            return pathArr.compactMap { if case let .str(s) = $0 { return s } else { return nil } }
        }
        return RegisteredCredential(format: format, docType: docType, vctValues: vctValues, claims: claims)
    }

    public static func listFromJson(_ v: JsonValue?) -> [RegisteredCredential] {
        guard case let .arr(items)? = v else { return [] }
        return items.compactMap { fromJson($0) }
    }
}

/// The RP's self-declared registration data, carried in the OpenID4VP `verifier_info` `registrar_dataset`
/// element (ETSI TS 119 472-2 §6.3, REQ-RO-02). It is **self-declared**: only the request (WRPAC) signature
/// covers it, so it is NOT registrar-attested. The wallet uses it for display / the transaction log
/// (DASH_03) and — when no WRPRC is present — as the key into the registrar's TS5 API (`registryURI` +
/// `identifier`) to obtain the same information *registrar-signed*.
public struct RegistrarDataset {
    /// The RP's unique identifier value (`identifier[0].identifier`, e.g. "HOPAE-DEMO-VERIFIER-LU-01") — the
    /// key for a TS5 registry lookup. Note: this is the raw value, without a semantic prefix.
    public let identifier: String?
    public let registryURI: String?
    public let policyURI: String?
    public let intendedUseIdentifier: String?
    public let srvDescription: [RegistrationLocalizedText]
    public let purpose: [RegistrationLocalizedText]
    /// The credentials/claims the RP self-declares it is registered to request (REQ-RO-12).
    public let credentials: [RegisteredCredential]
    /// The raw dataset JSON, for the transaction log.
    public let raw: JsonValue

    public init(identifier: String?, registryURI: String?, policyURI: String?, intendedUseIdentifier: String?,
                srvDescription: [RegistrationLocalizedText], purpose: [RegistrationLocalizedText],
                credentials: [RegisteredCredential], raw: JsonValue) {
        self.identifier = identifier
        self.registryURI = registryURI
        self.policyURI = policyURI
        self.intendedUseIdentifier = intendedUseIdentifier
        self.srvDescription = srvDescription
        self.purpose = purpose
        self.credentials = credentials
        self.raw = raw
    }

    private static func langTexts(_ v: JsonValue?) -> [RegistrationLocalizedText] {
        guard case let .arr(items)? = v else { return [] }
        return items.compactMap { item -> RegistrationLocalizedText? in
            guard case let .str(lang)? = item["lang"] else { return nil }
            // registrar_dataset uses `content`; WRPRC uses `value` — accept either.
            if case let .str(t)? = item["content"] { return RegistrationLocalizedText(lang: lang, value: t) }
            if case let .str(t)? = item["value"] { return RegistrationLocalizedText(lang: lang, value: t) }
            return nil
        }
    }

    public static func fromData(_ data: JsonValue) -> RegistrarDataset {
        var identifier: String?
        if case let .arr(ids)? = data["identifier"], let first = ids.first, case let .str(v)? = first["identifier"] {
            identifier = v
        }
        var registryURI: String?
        if case let .str(s)? = data["registryURI"] { registryURI = s }
        var policyURI: String?
        if case let .str(s)? = data["policyURI"] { policyURI = s }
        var intendedUseIdentifier: String?
        if case let .str(s)? = data["intendedUseIdentifier"] { intendedUseIdentifier = s }
        return RegistrarDataset(
            identifier: identifier,
            registryURI: registryURI,
            policyURI: policyURI,
            intendedUseIdentifier: intendedUseIdentifier,
            srvDescription: langTexts(data["srvDescription"]),
            purpose: langTexts(data["purpose"]),
            credentials: RegisteredCredential.listFromJson(data["credential"]),
            raw: data
        )
    }
}

/// One requested attribute the RP is not registered to request (RPRC_21).
public struct UnregisteredClaim: Equatable {
    public let credentialQueryId: String
    public let format: String
    public let path: [String]
    public init(credentialQueryId: String, format: String, path: [String]) {
        self.credentialQueryId = credentialQueryId
        self.format = format
        self.path = path
    }
}

/// Attribute-scope check (ETSI TS 119 475 RPRC_21): the requested claim paths a Relying Party is **not**
/// registered to request. An empty result means every requested attribute is within the RP's registration.
public enum RegistrationScope {
    /// Requested DCQL claim paths not covered by `registered`. Wildcard paths are skipped (indeterminate).
    public static func unregistered(_ dcql: DcqlQuery, registered: [RegisteredCredential]) -> [UnregisteredClaim] {
        if registered.isEmpty { return [] }
        var out: [UnregisteredClaim] = []
        for cq in dcql.credentials {
            let matching = registered.filter { $0.format == cq.format && metaMatches(cq.meta, $0) }
            for claim in cq.claims {
                guard let path = concretePath(claim.path) else { continue } // skip wildcard paths
                if !matching.contains(where: { $0.claims.contains(path) }) {
                    out.append(UnregisteredClaim(credentialQueryId: cq.id, format: cq.format, path: path))
                }
            }
        }
        return out
    }

    /// A DCQL path as plain strings, or nil when it contains a wildcard (can't be pinned to a fixed path).
    private static func concretePath(_ path: [PathElement]) -> [String]? {
        var out: [String] = []
        for e in path {
            switch e {
            case let .key(k): out.append(k)
            case let .index(i): out.append(String(i))
            case .wildcard: return nil
            }
        }
        return out
    }

    private static func metaMatches(_ meta: CredentialMeta?, _ rc: RegisteredCredential) -> Bool {
        guard let meta else { return true }
        if let dt = meta.doctypeValue, dt != rc.docType { return false }
        if let vct = meta.vctValues {
            guard let rcVct = rc.vctValues, vct.contains(where: { rcVct.contains($0) }) else { return false }
        }
        return true
    }
}
