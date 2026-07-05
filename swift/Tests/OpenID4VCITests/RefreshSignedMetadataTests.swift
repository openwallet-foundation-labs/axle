import CborCose
import Foundation
import SdJwt
import WalletAPI
import WalletTestKit
import XCTest
@testable import OpenID4VCI

/// Minor HAIP gaps: refresh-token reissuance (RFC 6749 §6) and signed issuer metadata (§11.2.3).
final class RefreshSignedMetadataTests: XCTestCase {

    private let now: Int64 = 1_700_000_000

    private struct TestRng: Rng {
        func nextBytes(_ size: Int) -> [UInt8] { (0..<size).map { UInt8(($0 + 1) & 0xff) } }
    }

    private struct TestVerifier: SignedMetadataVerifier {
        let key: EcPublicKey
        func verify(signedMetadataJws: String) async throws -> JsonValue {
            let jws = try Jws.parse(signedMetadataJws)
            guard jws.verify(key: key, expected: .es256) else { throw VciError.metadata("bad signed_metadata signature") }
            return try JsonValue.parse(try Base64Url.decodeToString(jws.payloadB64))
        }
    }

    private func makeKeys(_ area: SoftwareSecureArea) async throws -> IssuanceKeys {
        let proofKey = try await area.createKey(spec: KeySpec(secureArea: area.id, algorithm: .es256))
        let dpopKey = try await area.createKey(spec: KeySpec(secureArea: area.id, algorithm: .es256))
        return IssuanceKeys(
            proofSigner: SecureAreaJwsSigner(area: area, key: proofKey.handle, algorithm: .es256), proofPublicKey: proofKey.publicKey,
            dpopSigner: SecureAreaJwsSigner(area: area, key: dpopKey.handle, algorithm: .es256), dpopPublicKey: dpopKey.publicKey
        )
    }

    private func signMetadata(_ area: SoftwareSecureArea, _ issuerKey: KeyInfo, _ payload: JsonValue) async throws -> String {
        let header = JsonValue.obj([("alg", .str("ES256")), ("typ", .str("jwt"))])
        let jws = try await Jws.sign(header: header, payload: [UInt8](payload.serialize().utf8),
                                     signer: SecureAreaJwsSigner(area: area, key: issuerKey.handle, algorithm: .es256))
        return jws.compact()
    }

    func testReissueWithRefreshToken() async throws {
        let area = SoftwareSecureArea()
        let issuerKey = try await area.createKey(spec: KeySpec(secureArea: area.id, algorithm: .es256))
        let mock = MockIssuer(area: area, issuerKey: issuerKey, now: now)
        let client = Openid4VciClient(http: mock, rng: TestRng(), clock: { self.now })

        let offer = try CredentialOffer.parse(mock.credentialOfferJson)
        let first = try await client.issueWithPreAuthorizedCode(offer: offer, configurationId: "eu.europa.ec.eudi.pid.1", keys: try await makeKeys(area), txCode: "1234")
        XCTAssertEqual(1, first.credentials.count)
        XCTAssertTrue(first.canReissue, "issuer granted a refresh token")

        let renewed = try await client.reissue(first, keys: try await makeKeys(area))
        XCTAssertEqual(1, renewed.credentials.count)
        XCTAssertTrue(renewed.canReissue)
    }

    func testRequireSignedUsesVerifiedMetadata() async throws {
        let area = SoftwareSecureArea()
        let issuerKey = try await area.createKey(spec: KeySpec(secureArea: area.id, algorithm: .es256))
        let mock = MockIssuer(area: area, issuerKey: issuerKey, now: now)
        let jwt = try await signMetadata(area, issuerKey, .obj([
            ("credential_issuer", .str("https://issuer.example")),
            ("nonce_endpoint", .str("https://issuer.example/signed-nonce")),
        ]))
        await mock.setSignedMetadata(jwt)
        let client = Openid4VciClient(http: mock, rng: TestRng(), clock: { self.now }, metadataPolicy: .requireSigned(TestVerifier(key: issuerKey.publicKey)))

        let meta = try await client.loadIssuerMetadata("https://issuer.example")
        XCTAssertEqual("https://issuer.example", meta.credentialIssuer)
        XCTAssertEqual("https://issuer.example/signed-nonce", meta.nonceEndpoint) // verified claim overrode fetched JSON
    }

    func testRequireSignedRejectsUnsignedMetadata() async throws {
        let area = SoftwareSecureArea()
        let issuerKey = try await area.createKey(spec: KeySpec(secureArea: area.id, algorithm: .es256))
        let mock = MockIssuer(area: area, issuerKey: issuerKey, now: now) // no signed metadata
        let client = Openid4VciClient(http: mock, rng: TestRng(), clock: { self.now }, metadataPolicy: .requireSigned(TestVerifier(key: issuerKey.publicKey)))

        do { _ = try await client.loadIssuerMetadata("https://issuer.example"); XCTFail("expected metadata error") }
        catch VciError.metadata {}
    }

    func testRequireSignedRejectsBadSignature() async throws {
        let area = SoftwareSecureArea()
        let issuerKey = try await area.createKey(spec: KeySpec(secureArea: area.id, algorithm: .es256))
        let rogue = try await area.createKey(spec: KeySpec(secureArea: area.id, algorithm: .es256))
        let mock = MockIssuer(area: area, issuerKey: issuerKey, now: now)
        await mock.setSignedMetadata(try await signMetadata(area, rogue, .obj([("credential_issuer", .str("https://issuer.example"))])))
        let client = Openid4VciClient(http: mock, rng: TestRng(), clock: { self.now }, metadataPolicy: .requireSigned(TestVerifier(key: issuerKey.publicKey)))

        do { _ = try await client.loadIssuerMetadata("https://issuer.example"); XCTFail("expected bad signature") }
        catch VciError.metadata {}
    }
}
