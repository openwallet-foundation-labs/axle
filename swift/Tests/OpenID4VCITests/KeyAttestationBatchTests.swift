import Foundation
import SdJwt
import WalletAPI
import WalletTestKit
import XCTest
@testable import OpenID4VCI

/// HAIP hardening: Key Attestation in the proof header, and batch issuance (proofs array).
final class KeyAttestationBatchTests: XCTestCase {

    private let now: Int64 = 1_700_000_000

    private struct TestRng: Rng {
        func nextBytes(_ size: Int) -> [UInt8] { (0..<size).map { UInt8(($0 + 1) & 0xff) } }
    }
    private struct FixedKeyAttestation: KeyAttestationSource {
        func attestation(cNonce: String?) async throws -> String { "eyJ.key-attestation.jwt" }
    }

    func testKeyAttestationCarriedInProofHeader() async throws {
        let area = SoftwareSecureArea()
        let issuerKey = try await area.createKey(spec: KeySpec(secureArea: area.id, algorithm: .es256))
        let mock = MockIssuer(area: area, issuerKey: issuerKey, now: now)
        await mock.setRequiresKeyAttestation(true)
        let proofKey = try await area.createKey(spec: KeySpec(secureArea: area.id, algorithm: .es256))
        let dpopKey = try await area.createKey(spec: KeySpec(secureArea: area.id, algorithm: .es256))
        let keys = IssuanceKeys(
            proofSigner: SecureAreaJwsSigner(area: area, key: proofKey.handle, algorithm: .es256), proofPublicKey: proofKey.publicKey,
            dpopSigner: SecureAreaJwsSigner(area: area, key: dpopKey.handle, algorithm: .es256), dpopPublicKey: dpopKey.publicKey
        )
        let client = Openid4VciClient(http: mock, rng: TestRng(), clock: { self.now }, keyAttestation: FixedKeyAttestation())

        let offer = try CredentialOffer.parse(mock.credentialOfferJson)
        let response = try await client.issueWithPreAuthorizedCode(offer: offer, configurationId: "eu.europa.ec.eudi.pid.1", keys: keys, txCode: "1234")

        XCTAssertEqual(1, response.credentials.count)
        let seen = await mock.seenKeyAttestation
        XCTAssertEqual("eyJ.key-attestation.jwt", seen) // issuer saw the key_attestation in the proof header
    }

    /// Shape 2: attestation required + a batch → ONE jwt proof (first-key PoP) carrying the batch attestation,
    /// never one-jwt-per-key (the N×N shape the issuer rejects).
    func testBatchWithAttestationSendsExactlyOneJwtProof() async throws {
        let area = SoftwareSecureArea()
        let issuerKey = try await area.createKey(spec: KeySpec(secureArea: area.id, algorithm: .es256))
        let mock = MockIssuer(area: area, issuerKey: issuerKey, now: now)
        await mock.setRequiresKeyAttestation(true)
        func key() async throws -> KeyInfo { try await area.createKey(spec: KeySpec(secureArea: area.id, algorithm: .es256)) }
        func signer(_ k: KeyInfo) -> SecureAreaJwsSigner { SecureAreaJwsSigner(area: area, key: k.handle, algorithm: .es256) }
        let k1 = try await key(); let k2 = try await key(); let k3 = try await key(); let dpopKey = try await key()
        let keys = IssuanceKeys(
            proofSigner: signer(k1), proofPublicKey: k1.publicKey,
            dpopSigner: signer(dpopKey), dpopPublicKey: dpopKey.publicKey,
            additionalProofKeys: [ProofKey(signer: signer(k2), publicKey: k2.publicKey), ProofKey(signer: signer(k3), publicKey: k3.publicKey)],
            keyAttestation: FixedKeyAttestation()
        )
        let client = Openid4VciClient(http: mock, rng: TestRng(), clock: { self.now })

        let offer = try CredentialOffer.parse(mock.credentialOfferJson)
        _ = try await client.issueWithPreAuthorizedCode(offer: offer, configurationId: "eu.europa.ec.eudi.pid.1", keys: keys, txCode: "1234")

        let proofCount = await mock.seenProofCount
        XCTAssertEqual(1, proofCount, "the batch goes in attested_keys → exactly one jwt proof, not N")
        let seen = await mock.seenKeyAttestation
        XCTAssertEqual("eyJ.key-attestation.jwt", seen, "the batch attestation rides in that proof's header")
    }

    /// A config that mandates key attestation, with no attestation source available → the client refuses.
    func testAttestationRequiredButNoSourceThrows() async throws {
        let area = SoftwareSecureArea()
        let issuerKey = try await area.createKey(spec: KeySpec(secureArea: area.id, algorithm: .es256))
        let mock = MockIssuer(area: area, issuerKey: issuerKey, now: now)
        await mock.setRequiresKeyAttestation(true)
        let proofKey = try await area.createKey(spec: KeySpec(secureArea: area.id, algorithm: .es256))
        let dpopKey = try await area.createKey(spec: KeySpec(secureArea: area.id, algorithm: .es256))
        let keys = IssuanceKeys(
            proofSigner: SecureAreaJwsSigner(area: area, key: proofKey.handle, algorithm: .es256), proofPublicKey: proofKey.publicKey,
            dpopSigner: SecureAreaJwsSigner(area: area, key: dpopKey.handle, algorithm: .es256), dpopPublicKey: dpopKey.publicKey
        )
        let client = Openid4VciClient(http: mock, rng: TestRng(), clock: { self.now }) // no keyAttestation source

        let offer = try CredentialOffer.parse(mock.credentialOfferJson)
        do {
            _ = try await client.issueWithPreAuthorizedCode(offer: offer, configurationId: "eu.europa.ec.eudi.pid.1", keys: keys, txCode: "1234")
            XCTFail("must refuse when attestation is required but no source is configured")
        } catch { /* VciError.unsupported */ }
    }

    func testBatchIssuanceYieldsOneCredentialPerProofKey() async throws {
        let area = SoftwareSecureArea()
        let issuerKey = try await area.createKey(spec: KeySpec(secureArea: area.id, algorithm: .es256))
        let mock = MockIssuer(area: area, issuerKey: issuerKey, now: now)

        func key() async throws -> KeyInfo { try await area.createKey(spec: KeySpec(secureArea: area.id, algorithm: .es256)) }
        func signer(_ k: KeyInfo) -> SecureAreaJwsSigner { SecureAreaJwsSigner(area: area, key: k.handle, algorithm: .es256) }
        let k1 = try await key(); let k2 = try await key(); let k3 = try await key(); let dpopKey = try await key()
        let keys = IssuanceKeys(
            proofSigner: signer(k1), proofPublicKey: k1.publicKey,
            dpopSigner: signer(dpopKey), dpopPublicKey: dpopKey.publicKey,
            additionalProofKeys: [ProofKey(signer: signer(k2), publicKey: k2.publicKey), ProofKey(signer: signer(k3), publicKey: k3.publicKey)]
        )
        let client = Openid4VciClient(http: mock, rng: TestRng(), clock: { self.now })

        let offer = try CredentialOffer.parse(mock.credentialOfferJson)
        let response = try await client.issueWithPreAuthorizedCode(offer: offer, configurationId: "eu.europa.ec.eudi.pid.1", keys: keys, txCode: "1234")

        let proofCount = await mock.seenProofCount
        XCTAssertEqual(3, proofCount, "issuer received one proof per key")
        XCTAssertEqual(3, response.credentials.count, "one credential issued per proof")
        XCTAssertEqual(3, Set(response.credentials.map { $0.credential }).count, "credentials are distinct")
    }
}
