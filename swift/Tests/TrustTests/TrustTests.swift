import CborCose
import Crypto
import Foundation
import SdJwt
import WalletAPI
import X509
import XCTest
@testable import OpenID4VP
@testable import Trust

final class TrustTests: XCTestCase {

    private let validAt = Date(timeIntervalSince1970: 1_700_000_000)

    // ---- test certificate hierarchy (swift-certificates) ----

    private struct Cert {
        let certificate: Certificate
        let key: P256.Signing.PrivateKey
        var der: [UInt8] { get throws { try X509Support.der(certificate) } }
    }

    private func makeCa(_ cn: String = "Test CA") throws -> Cert {
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
            issuerPrivateKey: Certificate.PrivateKey(key)
        )
        return Cert(certificate: cert, key: key)
    }

    private func makeLeaf(_ ca: Cert, cn: String, dns: String? = nil,
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
            issuerPrivateKey: Certificate.PrivateKey(ca.key)
        )
        return Cert(certificate: cert, key: key)
    }

    private struct LeafSigner: JwsSigner {
        let algorithm: SigningAlgorithm = .es256
        let d: Data
        func sign(_ signingInput: [UInt8]) async throws -> [UInt8] {
            let key = try P256.Signing.PrivateKey(rawRepresentation: d)
            return [UInt8](try key.signature(for: Data(signingInput)).rawRepresentation)
        }
    }

    private func signedRequest(_ leaf: Cert, _ payload: String) async throws -> Jws {
        let header = JsonValue.obj([
            ("alg", .str("ES256")),
            ("typ", .str("oauth-authz-req+jwt")),
            ("x5c", .arr([.str(Data(try leaf.der).base64EncodedString())])),
        ])
        return try await Jws.sign(header: header, payload: [UInt8](payload.utf8), signer: LeafSigner(d: leaf.key.rawRepresentation))
    }

    // ---- chain validation ----

    func testChainValidatesToAnchor() async throws {
        let ca = try makeCa()
        let leaf = try makeLeaf(ca, cn: "Leaf")
        let chain = try await X509ChainValidator(anchors: TrustAnchors(roots: [ca.certificate]), validationTime: validAt).validate([try leaf.der])
        XCTAssertEqual(1, chain.count)
    }

    func testDynamicAnchorSourceRefreshes() async throws {
        // Source trusts only a rogue CA, then updates to the real one — the validator picks up
        // the new anchors on the next validate() with no rebuild.
        let realCa = try makeCa("Real CA")
        let rogueCa = try makeCa("Rogue CA")
        let leaf = try makeLeaf(realCa, cn: "Leaf")

        final class MutableSource: TrustAnchorSource, @unchecked Sendable {
            var current: TrustAnchors
            init(_ a: TrustAnchors) { current = a }
            func anchors() async -> TrustAnchors { current }
        }
        let source = MutableSource(TrustAnchors(roots: [rogueCa.certificate]))
        let validator = X509ChainValidator(anchorSource: source, validationTime: validAt)

        do { _ = try await validator.validate([try leaf.der]); XCTFail("rogue-only should reject") } catch is TrustError {}
        source.current = TrustAnchors(roots: [realCa.certificate])          // trust list "refreshes"
        let chain = try await validator.validate([try leaf.der])            // now trusted
        XCTAssertEqual(1, chain.count)
    }

    func testUntrustedCaRejected() async throws {
        let ca = try makeCa("Real CA")
        let rogue = try makeCa("Rogue CA")
        let leaf = try makeLeaf(ca, cn: "Leaf")
        let validator = X509ChainValidator(anchors: TrustAnchors(roots: [rogue.certificate]), validationTime: validAt)
        do { _ = try await validator.validate([try leaf.der]); XCTFail("should reject") } catch is TrustError {}
    }

    func testExpiredLeafRejected() async throws {
        let ca = try makeCa()
        let leaf = try makeLeaf(ca, cn: "Leaf", notAfter: Date(timeIntervalSince1970: 1_699_999_000))
        let validator = X509ChainValidator(anchors: TrustAnchors(roots: [ca.certificate]), validationTime: validAt)
        do { _ = try await validator.validate([try leaf.der]); XCTFail("should reject expired") } catch is TrustError {}
    }

    // ---- OpenID4VP request verification ----

    func testX509SanDnsTrusted() async throws {
        let ca = try makeCa()
        let leaf = try makeLeaf(ca, cn: "Verifier", dns: "verifier.example.com")
        let verifier = X509RequestVerifier(validator: X509ChainValidator(anchors: TrustAnchors(roots: [ca.certificate]), validationTime: validAt))
        let jws = try await signedRequest(leaf, #"{"nonce":"n"}"#)
        let info = try await verifier.verifyRequestObject(jws, clientId: "x509_san_dns:verifier.example.com", scheme: "x509_san_dns")
        XCTAssertTrue(info.trusted)
        XCTAssertEqual("Verifier", info.commonName)
    }

    func testX509SanDnsMismatchRejected() async throws {
        let ca = try makeCa()
        let leaf = try makeLeaf(ca, cn: "Verifier", dns: "verifier.example.com")
        let verifier = X509RequestVerifier(validator: X509ChainValidator(anchors: TrustAnchors(roots: [ca.certificate]), validationTime: validAt))
        let jws = try await signedRequest(leaf, #"{"nonce":"n"}"#)
        do {
            _ = try await verifier.verifyRequestObject(jws, clientId: "x509_san_dns:evil.example.com", scheme: "x509_san_dns")
            XCTFail("should reject")
        } catch { /* VpError.verifierNotTrusted */ }
    }

    func testX509HashTrusted() async throws {
        let ca = try makeCa()
        let leaf = try makeLeaf(ca, cn: "Verifier")
        let validator = X509ChainValidator(anchors: TrustAnchors(roots: [ca.certificate]), validationTime: validAt)
        let thumbprint = try X509Support.sha256Thumbprint(leaf.certificate)
        let jws = try await signedRequest(leaf, #"{"nonce":"n"}"#)
        let info = try await X509RequestVerifier(validator: validator).verifyRequestObject(jws, clientId: "x509_hash:\(thumbprint)", scheme: "x509_hash")
        XCTAssertTrue(info.trusted)
    }

    func testTamperedRequestRejected() async throws {
        let ca = try makeCa()
        let leaf = try makeLeaf(ca, cn: "Verifier", dns: "verifier.example.com")
        let validator = X509ChainValidator(anchors: TrustAnchors(roots: [ca.certificate]), validationTime: validAt)
        let jws = try await signedRequest(leaf, #"{"nonce":"n"}"#)
        let tampered = Jws(header: jws.header, headerB64: jws.headerB64, payloadB64: Base64Url.encode([UInt8](#"{"nonce":"evil"}"#.utf8)), signature: jws.signature)
        do {
            _ = try await X509RequestVerifier(validator: validator).verifyRequestObject(tampered, clientId: "x509_san_dns:verifier.example.com", scheme: "x509_san_dns")
            XCTFail("should reject tampered")
        } catch {}
    }

    // ---- verifier_info: registrar_dataset (ETSI TS 119 472-2 §6.3) ----

    private func registrarVerifier() throws -> WRPRCVerifier {
        let ca = try makeCa("Registrar CA")
        return WRPRCVerifier(validator: X509ChainValidator(anchors: TrustAnchors(roots: [ca.certificate]), validationTime: validAt),
                             time: JwtTimeValidator(now: { self.validAt }))
    }

    /// A `registrar_dataset` (self-declared, no WRPRC) is parsed and surfaced, attested = false.
    func testVerifierInfoDatasetParsed() async throws {
        let ca = try makeCa()
        let leaf = try makeLeaf(ca, cn: "Verifier", dns: "verifier.example.com")
        let validator = X509ChainValidator(anchors: TrustAnchors(roots: [ca.certificate]), validationTime: validAt)
        let payload = #"{"nonce":"n","verifier_info":[{"format":"registrar_dataset","data":{"identifier":[{"type":"LEI","identifier":"HOPAE-TEST-RP"}],"registryURI":"https://registrar.example/registrar","policyURI":"https://rp.example/privacy","intendedUseIdentifier":"use-1","srvDescription":[{"lang":"en","content":"Test RP"}],"purpose":[{"lang":"en","content":"Age check"}],"credential":[{"format":"mso_mdoc","meta":{"doctype_value":"org.iso.18013.5.1.mDL"},"claim":[{"path":["org.iso.18013.5.1","given_name"]}]}]}}]}"#
        let jws = try await signedRequest(leaf, payload)
        let info = try await X509RequestVerifier(validator: validator, wrprcVerifier: try registrarVerifier())
            .verifyRequestObject(jws, clientId: "x509_san_dns:verifier.example.com", scheme: "x509_san_dns")
        let reg = try XCTUnwrap(info.registration)
        XCTAssertFalse(reg.attested, "a dataset-only registration is not registrar-attested")
        XCTAssertEqual("HOPAE-TEST-RP", reg.dataset?.identifier)
        XCTAssertEqual("https://registrar.example/registrar", reg.dataset?.registryURI)
        XCTAssertEqual("https://rp.example/privacy", reg.dataset?.policyURI)
        XCTAssertEqual(1, reg.registeredCredentials.count)
        XCTAssertEqual([["org.iso.18013.5.1", "given_name"]], reg.registeredCredentials.first?.claims)
    }

    /// Presence matrix (§2): a `registration_cert` without the mandatory `registrar_dataset` is malformed.
    func testRegistrationCertWithoutDatasetRejected() async throws {
        let ca = try makeCa()
        let leaf = try makeLeaf(ca, cn: "Verifier", dns: "verifier.example.com")
        let validator = X509ChainValidator(anchors: TrustAnchors(roots: [ca.certificate]), validationTime: validAt)
        let fakeCert = Base64Url.encode([UInt8]("not-a-real-wrprc".utf8))
        let payload = #"{"nonce":"n","verifier_info":[{"format":"registration_cert","data":"\#(fakeCert)"}]}"#
        let jws = try await signedRequest(leaf, payload)
        do {
            _ = try await X509RequestVerifier(validator: validator, wrprcVerifier: try registrarVerifier())
                .verifyRequestObject(jws, clientId: "x509_san_dns:verifier.example.com", scheme: "x509_san_dns")
            XCTFail("a registration_cert without a registrar_dataset must be rejected")
        } catch { /* VpError.invalidRequest */ }
    }

    /// No `verifier_info` at all → registration stays nil even with registrar trust configured (interop).
    func testVerifierInfoAbsentRegistrationNil() async throws {
        let ca = try makeCa()
        let leaf = try makeLeaf(ca, cn: "Verifier", dns: "verifier.example.com")
        let validator = X509ChainValidator(anchors: TrustAnchors(roots: [ca.certificate]), validationTime: validAt)
        let jws = try await signedRequest(leaf, #"{"nonce":"n"}"#)
        let info = try await X509RequestVerifier(validator: validator, wrprcVerifier: try registrarVerifier())
            .verifyRequestObject(jws, clientId: "x509_san_dns:verifier.example.com", scheme: "x509_san_dns")
        XCTAssertNil(info.registration)
    }

    // ---- issuer key resolution ----

    func testX5cIssuerKeyResolves() async throws {
        let ca = try makeCa()
        let leaf = try makeLeaf(ca, cn: "PID DS")
        let resolver = X5cIssuerKeyResolver(validator: X509ChainValidator(anchors: TrustAnchors(roots: [ca.certificate]), validationTime: validAt))
        let header = JsonValue.obj([("x5c", .arr([.str(Data(try leaf.der).base64EncodedString())]))])
        let key = try await resolver.resolve(iss: "https://issuer.example", header: header)
        XCTAssertEqual(try X509Support.ecPublicKey(leaf.certificate).x, key.publicKey.x)
    }

    // ---- real EUDI trust anchor ----

    func testRealEudiCaLoads() throws {
        let url = Bundle.module.url(forResource: "pid_issuer_ca_ut_02", withExtension: "der")!
        let der = [UInt8](try Data(contentsOf: url))
        let ca = try X509Support.parse(der)
        XCTAssertEqual(ca.subject, ca.issuer, "IACA is a self-signed root")
    }
}
