import Crypto
import Foundation
import SdJwt
import Trust
import WalletAPI
import X509

/// Generates EC certificate hierarchies with SAN + signed OpenID4VP request objects for reader-trust tests.
public enum TestCerts {

    public struct Cert {
        public let certificate: Certificate
        public let key: P256.Signing.PrivateKey
        public var der: [UInt8] { get throws { try X509Support.der(certificate) } }
    }

    public static func makeCa(_ cn: String = "Test CA") throws -> Cert {
        let key = P256.Signing.PrivateKey()
        let name = try DistinguishedName { CommonName(cn) }
        let cert = try Certificate(
            version: .v3,
            serialNumber: Certificate.SerialNumber(),
            publicKey: Certificate.PublicKey(key.publicKey),
            notValidBefore: Date(timeIntervalSince1970: 1_600_000_000),
            notValidAfter: Date(timeIntervalSince1970: 2_000_000_000),
            issuer: name, subject: name,
            signatureAlgorithm: .ecdsaWithSHA256,
            extensions: try Certificate.Extensions {
                Critical(BasicConstraints.isCertificateAuthority(maxPathLength: nil))
            },
            issuerPrivateKey: Certificate.PrivateKey(key))
        return Cert(certificate: cert, key: key)
    }

    public static func makeLeaf(_ ca: Cert, cn: String, dns: String? = nil,
                                notAfter: Date = Date(timeIntervalSince1970: 2_000_000_000)) throws -> Cert {
        let key = P256.Signing.PrivateKey()
        let cert = try Certificate(
            version: .v3,
            serialNumber: Certificate.SerialNumber(),
            publicKey: Certificate.PublicKey(key.publicKey),
            notValidBefore: Date(timeIntervalSince1970: 1_600_000_000),
            notValidAfter: notAfter,
            issuer: ca.certificate.subject,
            subject: try DistinguishedName { CommonName(cn) },
            signatureAlgorithm: .ecdsaWithSHA256,
            extensions: try Certificate.Extensions {
                Critical(BasicConstraints.notCertificateAuthority)
                if let dns { SubjectAlternativeNames([.dnsName(dns)]) }
            },
            issuerPrivateKey: Certificate.PrivateKey(ca.key))
        return Cert(certificate: cert, key: key)
    }

    /// A JAR (signed request object) delivered inline via `request=`, with the reader cert in the x5c header.
    public static func signedRequestUrl(leaf: Cert, clientId: String, scheme: String, requestClaims: String) async throws -> String {
        let header = JsonValue.obj([
            ("alg", .str("ES256")),
            ("typ", .str("oauth-authz-req+jwt")),
            ("x5c", .arr([.str(Data(try leaf.der).base64EncodedString())])),
        ])
        let jws = try await Jws.sign(header: header, payload: [UInt8](requestClaims.utf8), signer: LeafSigner(d: leaf.key.rawRepresentation))
        func enc(_ s: String) -> String { s.addingPercentEncoding(withAllowedCharacters: .alphanumerics) ?? s }
        return "openid4vp://?client_id=\(enc(clientId))&client_id_scheme=\(scheme)&request=\(enc(jws.compact()))"
    }

    private struct LeafSigner: JwsSigner {
        let algorithm: SigningAlgorithm = .es256
        let d: Data
        func sign(_ signingInput: [UInt8]) async throws -> [UInt8] {
            let key = try P256.Signing.PrivateKey(rawRepresentation: d)
            return [UInt8](try key.signature(for: Data(signingInput)).rawRepresentation)
        }
    }
}
