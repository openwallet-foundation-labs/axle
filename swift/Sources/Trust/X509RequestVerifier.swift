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
        let chain = try await validator.validate(x5c) // throws if chain not trusted
        let leaf = chain[0]

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

        let chainDer = try chain.map { try X509Support.der($0) }

        // ETSI TS 119 475 / TS 119 472-2: verify the RP registration cert (WRPRC), when configured and present.
        // A present-but-invalid registration_cert rejects the request; an absent one leaves registration nil
        // (interop with verifiers that don't yet carry a WRPRC).
        var registration: RegistrationInfo?
        if let wrprcVerifier, let wrprc = Self.extractRegistrationCert(jws) {
            let verified = try await wrprcVerifier.verify(wrprc, wrpacLeafDer: chainDer[0])
            registration = RegistrationInfo(
                subject: verified.subject,
                entitlements: verified.entitlements,
                purpose: verified.purpose.map { RegistrationLocalizedText(lang: $0.lang, value: $0.value) },
                intermediarySub: verified.intermediary?.sub,
                intermediaryName: verified.intermediary?.name,
                status: verified.status
            )
        }

        return VerifierInfo(
            clientId: clientId, clientIdScheme: scheme,
            certificateChainDer: chainDer,
            commonName: X509Support.commonName(leaf), trusted: true,
            registration: registration
        )
    }

    /// Pulls the WRPRC (a `rc-wrp+jwt` compact JWS) out of the request object's `verifier_info` array: the
    /// element whose `format` is `"registration_cert"` carries it as `base64url(serialized WRPRC)`
    /// (ETSI TS 119 472-2 §6.3, REQ-RO-13/15). Returns nil when no such element is present or decodable.
    static func extractRegistrationCert(_ jws: Jws) -> String? {
        guard let text = String(bytes: jws.payloadBytes, encoding: .utf8),
              let claims = try? JsonValue.parse(text),
              case let .arr(infos)? = claims["verifier_info"] else { return nil }
        for info in infos {
            guard case let .str(format)? = info["format"], format == "registration_cert",
                  case let .str(data)? = info["data"] else { continue }
            guard let bytes = try? Base64Url.decode(data),
                  let wrprc = String(bytes: bytes, encoding: .utf8) else { return nil }
            return wrprc
        }
        return nil
    }
}
