import CborCose
import Foundation
import OpenID4VP
import SdJwt
import WalletAPI
import X509

/// A localized string (BCP-47 `lang` + `value`) as used in WRPRC `purpose` / `srv_description`.
public struct LocalizedText: Sendable, Equatable {
    public let lang: String
    public let value: String
    public init(lang: String, value: String) {
        self.lang = lang
        self.value = value
    }
}

/// The intermediary a Relying Party operates through (ETSI TS 119 475 Table 10 `intermediary`).
public struct Intermediary: Sendable, Equatable {
    /// The intermediary's semantic identifier (matches its own WRPAC; also carried in `act.sub`).
    public let sub: String
    /// The intermediary's user-facing name (`sname`).
    public let name: String?
    public init(sub: String, name: String?) {
        self.sub = sub
        self.name = name
    }
}

/// The result of validating a Wallet-Relying Party Registration Certificate.
public struct VerifiedWRPRC: Sendable {
    /// `sub` — the registered semantic identifier (e.g. `VATLU-12345678`), bound to the WRPAC. For an
    /// intermediated request this is always the **final** relying party, never the intermediary.
    public let subject: String
    /// `entitlements` — the EU-level roles asserted for the relying party (≥1).
    public let entitlements: [String]
    /// `purpose` — the declared intended-use, for display on the consent screen.
    public let purpose: [LocalizedText]
    /// The intermediary the RP operates through, when the request is intermediated (else nil).
    public let intermediary: Intermediary?
    /// The `credentials` the RP is registered to request (ETSI TS 119 475 §5.2.4) — each with its format,
    /// type meta and claim paths. Registrar-attested, so it is the authoritative input to the attribute-scope
    /// check (RPRC_21). Empty when the WRPRC declares no `credentials`.
    public let registeredCredentials: [RegisteredCredential]
    /// The full decoded payload, for any claim not surfaced above.
    public let claims: JsonValue
    /// The raw `status` claim (`{ status_list: { idx, uri } }`) to feed a Token Status List check.
    public let status: JsonValue?
}

/// Validates a Wallet-Relying Party Registration Certificate (ETSI TS 119 475), a `rc-wrp+jwt` signed
/// as a JAdES baseline (B-B) signature. It verifies the JAdES signature against the registrar CA and binds
/// the WRPRC to the already-validated WRPAC that signed the request: for a direct request the WRPAC
/// `organizationIdentifier` must equal the WRPRC `sub` (GEN-5.1.1-02); for an intermediated request the
/// request is signed by the intermediary, so the WRPAC must equal `intermediary.sub`/`act.sub` (RPRC_04)
/// while `sub` remains the final RP. It also extracts the entitlements / intended-use for the consent
/// screen. The caller is responsible for the Token Status List check using the returned `status` claim.
// `@unchecked Sendable`: WRPRCVerifier is an immutable value — a chain validator (Sendable) plus a pure
// time function — so it is safe to share across concurrency domains. The `@unchecked` is only needed because
// `JwtTimeValidator`'s clock closure is not itself marked `@Sendable`. It rides on the Sendable
// `X509RequestVerifier`, so without this the request verifier would warn (an error under Swift 6).
public struct WRPRCVerifier: @unchecked Sendable {
    public static let typ = "rc-wrp+jwt"
    /// JAdES B-B protected-header extensions this verifier understands (RFC 7515 §4.1.11).
    private static let understoodCrit: Set<String> = ["sigT", "b64"]

    private let validator: X509ChainValidator
    private let time: JwtTimeValidator

    /// - Parameter validator: a chain validator built over the **registrar CA** trust anchors.
    public init(validator: X509ChainValidator, time: JwtTimeValidator) {
        self.validator = validator
        self.time = time
    }

    /// Verify `wrprc` and bind it to the WRPAC leaf (`wrpacLeafDer`, already validated by the request verifier).
    public func verify(_ wrprc: String, wrpacLeafDer: [UInt8]) async throws -> VerifiedWRPRC {
        let jws = try Jws.parse(wrprc)

        // --- Protected header (ETSI TS 119 475 Table 5 + JAdES) ---
        guard case .str(Self.typ)? = jws.header["typ"] else {
            throw TrustError("WRPRC typ must be \(Self.typ)")
        }
        guard case let .str(alg)? = jws.header["alg"], alg == "ES256" else {
            throw TrustError("WRPRC alg must be ES256")
        }
        // `crit` must only list extensions we understand, else reject (RFC 7515 §4.1.11).
        if case let .arr(crit)? = jws.header["crit"] {
            for entry in crit {
                guard case let .str(name) = entry, Self.understoodCrit.contains(name) else {
                    throw TrustError("WRPRC declares an unsupported critical header")
                }
            }
        }
        // RFC 7797: only the standard base64url-encoded payload is supported (b64 true / absent).
        if case .bool(false)? = jws.header["b64"] {
            throw TrustError("WRPRC with an unencoded (b64=false) payload is not supported")
        }

        // --- Signature: chain to the registrar CA, then verify directly (JAdES has `crit`, so
        //     Jws.verify would reject it — RFC 7515 §4.1.11). ---
        guard let x5c = jws.x5c else { throw TrustError("WRPRC without x5c") }
        let chain = try await validator.validate(x5c)
        let leaf = chain[0]

        if case let .str(thumb)? = jws.header["x5t#S256"] {
            guard try X509Support.sha256Thumbprint(leaf) == thumb else {
                throw TrustError("WRPRC x5t#S256 does not match the signing certificate")
            }
        }

        let key = try X509Support.ecPublicKey(leaf)
        guard Ecdsa.verify(
            key: key,
            algorithm: SigningAlgorithm.es256.coseAlgorithm,
            data: jws.signingInput,
            rawSignature: jws.signature
        ) else {
            throw TrustError("WRPRC signature invalid")
        }

        // --- Payload ---
        let payload = try JsonValue.parse(String(decoding: jws.payloadBytes, as: UTF8.self))
        guard case .obj = payload else { throw TrustError("WRPRC payload is not a JSON object") }
        try time.validate(payload) // `exp` is optional per TS 119 475 Table 10; iat sanity only

        guard case let .str(subject)? = payload["sub"], !subject.isEmpty else {
            throw TrustError("WRPRC missing `sub`")
        }

        // intermediary (Table 10) + actor claim binding (GEN-5.2.4-09): when the RP operates through
        // an intermediary, `act.sub` must equal the intermediary's identifier.
        var intermediary: Intermediary?
        if case let .str(intSub)? = payload["intermediary"]?["sub"] {
            var intName: String?
            if case let .str(name)? = payload["intermediary"]?["sname"] { intName = name }
            if case let .str(actSub)? = payload["act"]?["sub"], actSub != intSub {
                throw TrustError("WRPRC act.sub (\(actSub)) does not match intermediary.sub (\(intSub))")
            }
            intermediary = Intermediary(sub: intSub, name: intName)
        }

        // Linkability (GEN-5.1.1-02 / RPRC_04): the Request Object is signed by a WRPAC whose
        // organizationIdentifier must equal the entity that actually sent the request. For a DIRECT request
        // that entity is the relying party itself (WRPRC `sub`); for an INTERMEDIATED request the signer is
        // the *intermediary*, so bind the presented WRPAC to `act`/`intermediary.sub` (the intermediary's own
        // access certificate) — `sub` stays the final RP, for display only.
        guard let orgId = X509Support.organizationIdentifier(fromDer: wrpacLeafDer) else {
            throw TrustError("WRPAC has no organizationIdentifier to bind the WRPRC against")
        }
        let boundIdentity = intermediary?.sub ?? subject
        guard orgId == boundIdentity else {
            let role = intermediary != nil ? "intermediary.sub" : "`sub`"
            throw TrustError("WRPRC \(role) (\(boundIdentity)) does not match WRPAC organizationIdentifier (\(orgId))")
        }

        // entitlements (≥1 EU-level role, GEN-5.2.4-03).
        var entitlements: [String] = []
        if case let .arr(items)? = payload["entitlements"] {
            for item in items {
                if case let .str(value) = item { entitlements.append(value) }
            }
        }
        guard !entitlements.isEmpty else { throw TrustError("WRPRC declares no entitlements") }

        // purpose (intended-use, localized).
        var purpose: [LocalizedText] = []
        if case let .arr(items)? = payload["purpose"] {
            for item in items {
                if case let .str(lang)? = item["lang"], case let .str(value)? = item["value"] {
                    purpose.append(LocalizedText(lang: lang, value: value))
                }
            }
        }

        // `credentials` (§5.2.4) — the attestation types + claim paths the RP is registered to request.
        let registeredCredentials = RegisteredCredential.listFromJson(payload["credentials"])

        return VerifiedWRPRC(
            subject: subject,
            entitlements: entitlements,
            purpose: purpose,
            intermediary: intermediary,
            registeredCredentials: registeredCredentials,
            claims: payload,
            status: payload["status"]
        )
    }
}
