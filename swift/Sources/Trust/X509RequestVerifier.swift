import Foundation
import OpenID4VP
import SdJwt

/// Verifies an OpenID4VP signed request object (OpenID4VP §5.10): the JWS signature against the
/// x5c leaf key, the certificate chain to a trust anchor, and the client_id scheme —
/// `x509_san_dns` (leaf SAN dNSName == client_id host) or `x509_hash`
/// (base64url(SHA-256(leaf DER)) == client_id value). The live EUDI verifier uses `x509_hash`.
public struct X509RequestVerifier: RequestTrustVerifier {
    private let validator: X509ChainValidator
    /// Optional WRPRC verifier (built over the registrar CA). When set, a `registration_cert` carried in the
    /// request's `verifier_info` is validated and bound to the WRPAC leaf; the result rides on `VerifierInfo`.
    private let wrprcVerifier: WRPRCVerifier?

    public init(validator: X509ChainValidator, wrprcVerifier: WRPRCVerifier? = nil) {
        self.validator = validator
        self.wrprcVerifier = wrprcVerifier
    }

    public func verifyRequestObject(_ jws: Jws, clientId: String, scheme: String) async throws -> VerifierInfo {
        guard let x5c = jws.x5c else { throw VpError.verifierNotTrusted("x509 request without x5c") }
        let leaf = try X509Support.parse(x5c[0]) // the request's signing cert — not yet trusted

        // --- Authenticity (HARD fail) --- a request whose signature does not verify, or whose client_id does
        // not identify this exact certificate, is forged / spoofed (not merely "untrusted") and is rejected.
        guard case let .str(algName)? = jws.header["alg"], let alg = signingAlgorithmFromJwsName(algName) else {
            throw VpError.invalidRequest("unsupported request alg")
        }
        guard jws.verify(key: try X509Support.ecPublicKey(leaf), expected: alg) else {
            throw VpError.verifierNotTrusted("request signature invalid")
        }
        switch scheme {
        case "x509_san_dns":
            let expected = clientId.hasPrefix("x509_san_dns:") ? String(clientId.dropFirst("x509_san_dns:".count)) : clientId
            guard X509Support.dnsNames(leaf).contains(where: { $0.caseInsensitiveCompare(expected) == .orderedSame }) else {
                throw VpError.verifierNotTrusted("client_id '\(expected)' not in certificate SAN dNSName")
            }
        case "x509_hash":
            let expected = clientId.hasPrefix("x509_hash:") ? String(clientId.dropFirst("x509_hash:".count)) : clientId
            guard try X509Support.sha256Thumbprint(leaf) == expected else {
                throw VpError.verifierNotTrusted("client_id hash does not match the certificate")
            }
        default:
            throw VpError.unsupported("client_id scheme '\(scheme)' for x509 verification")
        }

        // --- Trust (SOFT) --- whether the certificate chains to a trusted reader anchor. A failure is NOT an
        // error: it surfaces as `trusted = false` so the wallet can show "not trusted" and let the User decide.
        // Registration (WRPRC / registrar_dataset) is likewise best-effort — any problem yields no registration.
        let trusted = (try? await validator.validate(x5c)) != nil
        let registration = try? await buildRegistration(jws, x5c)

        return VerifierInfo(
            clientId: clientId, clientIdScheme: scheme,
            certificateChainDer: x5c,
            commonName: X509Support.commonName(leaf), trusted: trusted,
            registration: registration
        )
    }

    /// The RP's registration from `verifier_info` (ETSI TS 119 472-2 §6.3), when registrar trust is configured.
    /// Throws on a verification problem; the caller treats that as "no registration" (soft) so an untrusted /
    /// invalid registration does not block the presentation.
    private func buildRegistration(_ jws: Jws, _ x5c: [[UInt8]]) async throws -> RegistrationInfo? {
        guard let wrprcVerifier else { return nil }
        let (dataset, wrprc) = Self.extractVerifierInfo(jws)
        if let wrprc, dataset == nil {
            // Presence matrix (§2): a WRPRC without the mandatory dataset is malformed.
            throw VpError.invalidRequest("verifier_info carries a registration_cert but no registrar_dataset (REQ-RO-02)")
        } else if let wrprc {
            // Both present → the WRPRC wins (registrar-attested, offline-verifiable); dataset is for display/log.
            let verified = try await wrprcVerifier.verify(wrprc, wrpacLeafDer: x5c[0])
            return RegistrationInfo(
                subject: verified.subject,
                entitlements: verified.entitlements,
                purpose: verified.purpose.map { RegistrationLocalizedText(lang: $0.lang, value: $0.value) },
                intermediarySub: verified.intermediary?.sub,
                intermediaryName: verified.intermediary?.name,
                status: verified.status,
                attested: true,
                dataset: dataset,
                registeredCredentials: verified.registeredCredentials
            )
        } else if let dataset {
            // Dataset only → self-declared registration (not registrar-attested). The wallet layer may upgrade
            // it via the registrar's TS5 API when the User opts in (RPRC_16/18); until then `attested = false`.
            return RegistrationInfo(
                subject: dataset.identifier ?? "",
                entitlements: [],
                purpose: dataset.purpose.map { RegistrationLocalizedText(lang: $0.lang, value: $0.value) },
                intermediarySub: nil,
                intermediaryName: nil,
                status: nil,
                attested: false,
                dataset: dataset,
                registeredCredentials: dataset.credentials
            )
        }
        return nil
    }

    /// Reads the request object's `verifier_info` array (ETSI TS 119 472-2 §6.3): the self-declared
    /// `registrar_dataset` element and the optional `registration_cert` (the WRPRC as `base64url(serialized
    /// WRPRC)`, REQ-RO-13/15). Returns (dataset, wrprcCompactJws); either is nil when its element is absent
    /// or undecodable, and both are nil when there is no `verifier_info` at all.
    static func extractVerifierInfo(_ jws: Jws) -> (RegistrarDataset?, String?) {
        guard let text = String(bytes: jws.payloadBytes, encoding: .utf8),
              let claims = try? JsonValue.parse(text),
              case let .arr(infos)? = claims["verifier_info"] else { return (nil, nil) }
        var dataset: RegistrarDataset?
        var wrprc: String?
        for info in infos {
            guard case let .str(format)? = info["format"] else { continue }
            switch format {
            case "registrar_dataset":
                if let data = info["data"] { dataset = RegistrarDataset.fromData(data) }
            case "registration_cert":
                if case let .str(data)? = info["data"], let bytes = try? Base64Url.decode(data) {
                    wrprc = String(bytes: bytes, encoding: .utf8)
                }
            default:
                continue
            }
        }
        return (dataset, wrprc)
    }
}
