import CborCose
import Foundation
import SdJwt
import WalletAPI
import WalletTestKit
import XCTest
@testable import OpenID4VCI

/// OpenID4VCI §8.2.1 Appendix F.3 `attestation` proof type: a single Key Attestation JWT (with
/// `attested_keys`) sent as the proof, without a per-key proof of possession. Used only when the issuer
/// advertises it and the wallet opts in; otherwise the `jwt` proof type is used.
final class AttestationProofTests: XCTestCase {

    private let now: Int64 = 1_700_000_000

    private struct TestRng: Rng {
        func nextBytes(_ size: Int) -> [UInt8] { (0..<size).map { UInt8(($0 + 1) & 0xff) } }
    }

    /// A Key Attestation source that attests `attestedKeys` and binds the c_nonce (Appendix D.1).
    private struct TestAttestationSource: KeyAttestationSource {
        let area: SoftwareSecureArea
        let attKey: KeyHandle
        let attestedKeys: [EcPublicKey]
        let now: Int64
        func attestation(cNonce: String?) async throws -> String {
            var claims: [(String, JsonValue)] = [("iat", .numInt(now))]
            if let cNonce { claims.append(("nonce", .str(cNonce))) }
            claims.append(("attested_keys", .arr(attestedKeys.map { JwkEc.toJson($0) })))
            let header = JsonValue.obj([("typ", .str("keyattestation+jwt")), ("alg", .str("ES256"))])
            let signer = SecureAreaJwsSigner(area: area, key: attKey, algorithm: .es256)
            return try await Jws.sign(header: header, payload: [UInt8](JsonValue.obj(claims).serialize().utf8), signer: signer).compact()
        }
    }

    private func makeKeys(_ area: SoftwareSecureArea, _ proof: KeyInfo, _ dpop: KeyInfo) -> IssuanceKeys {
        IssuanceKeys(
            proofSigner: SecureAreaJwsSigner(area: area, key: proof.handle, algorithm: .es256), proofPublicKey: proof.publicKey,
            dpopSigner: SecureAreaJwsSigner(area: area, key: dpop.handle, algorithm: .es256), dpopPublicKey: dpop.publicKey
        )
    }

    func testUsesAttestationProofTypeWhenSupportedAndPreferred() async throws {
        let area = SoftwareSecureArea()
        let issuerKey = try await area.createKey(spec: KeySpec(secureArea: area.id, algorithm: .es256))
        let mock = MockIssuer(area: area, issuerKey: issuerKey, now: now)
        await mock.setSupportsAttestationProof(true)
        let proof = try await area.createKey(spec: KeySpec(secureArea: area.id, algorithm: .es256))
        let dpop = try await area.createKey(spec: KeySpec(secureArea: area.id, algorithm: .es256))
        let attKey = try await area.createKey(spec: KeySpec(secureArea: area.id, algorithm: .es256))
        let source = TestAttestationSource(area: area, attKey: attKey.handle, attestedKeys: [proof.publicKey], now: now)
        let client = Openid4VciClient(http: mock, rng: TestRng(), clock: { self.now }, keyAttestation: source, preferAttestationProof: true)

        let offer = try CredentialOffer.parse(mock.credentialOfferJson)
        let response = try await client.issueWithPreAuthorizedCode(offer: offer, configurationId: "eu.europa.ec.eudi.pid.1", keys: makeKeys(area, proof, dpop), txCode: "1234")

        XCTAssertEqual(1, response.credentials.count, "one credential per attested key")
        let seenAtt = await mock.seenAttestationProof
        let seenKa = await mock.seenKeyAttestation
        XCTAssertNotNil(seenAtt, "the attestation proof type was used")
        XCTAssertNil(seenKa, "no jwt-proof header path when the attestation proof type is used")
    }

    func testFallsBackToJwtProofWhenIssuerDoesNotSupportAttestation() async throws {
        // preferAttestationProof is set, but the issuer advertises only the jwt proof type → jwt is used,
        // carrying the attestation in the proof header instead.
        let area = SoftwareSecureArea()
        let issuerKey = try await area.createKey(spec: KeySpec(secureArea: area.id, algorithm: .es256))
        let mock = MockIssuer(area: area, issuerKey: issuerKey, now: now) // attestation proof type not advertised
        let proof = try await area.createKey(spec: KeySpec(secureArea: area.id, algorithm: .es256))
        let dpop = try await area.createKey(spec: KeySpec(secureArea: area.id, algorithm: .es256))
        let attKey = try await area.createKey(spec: KeySpec(secureArea: area.id, algorithm: .es256))
        let source = TestAttestationSource(area: area, attKey: attKey.handle, attestedKeys: [proof.publicKey], now: now)
        let client = Openid4VciClient(http: mock, rng: TestRng(), clock: { self.now }, keyAttestation: source, preferAttestationProof: true)

        let offer = try CredentialOffer.parse(mock.credentialOfferJson)
        _ = try await client.issueWithPreAuthorizedCode(offer: offer, configurationId: "eu.europa.ec.eudi.pid.1", keys: makeKeys(area, proof, dpop), txCode: "1234")

        let seenAtt = await mock.seenAttestationProof
        let seenProofCount = await mock.seenProofCount
        let seenKa = await mock.seenKeyAttestation
        XCTAssertNil(seenAtt, "the attestation proof type is not used when unsupported")
        XCTAssertEqual(1, seenProofCount, "a jwt proof was sent")
        XCTAssertNotNil(seenKa, "the attestation rides in the jwt proof header instead")
    }
}
