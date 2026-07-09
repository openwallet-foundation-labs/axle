import Foundation
import SdJwt
import WalletAPI
import WalletTestKit
import XCTest
@testable import OpenID4VCI

/// OpenID4VCI §8.2 `credential_identifiers`: when the token-response `authorization_details` bind concrete
/// dataset identifiers to a config, the Credential Request MUST carry a `credential_identifier` and MUST NOT
/// carry `credential_configuration_id`; otherwise it uses `credential_configuration_id`.
final class CredentialIdentifiersTests: XCTestCase {

    private let now: Int64 = 1_700_000_000

    private struct TestRng: Rng {
        func nextBytes(_ size: Int) -> [UInt8] { (0..<size).map { UInt8(($0 + 1) & 0xff) } }
    }

    private func makeKeys(_ area: SoftwareSecureArea) async throws -> IssuanceKeys {
        let proofKey = try await area.createKey(spec: KeySpec(secureArea: area.id, algorithm: .es256))
        let dpopKey = try await area.createKey(spec: KeySpec(secureArea: area.id, algorithm: .es256))
        return IssuanceKeys(
            proofSigner: SecureAreaJwsSigner(area: area, key: proofKey.handle, algorithm: .es256), proofPublicKey: proofKey.publicKey,
            dpopSigner: SecureAreaJwsSigner(area: area, key: dpopKey.handle, algorithm: .es256), dpopPublicKey: dpopKey.publicKey
        )
    }

    func testRequestsWithCredentialIdentifierWhenTokenBindsThem() async throws {
        let area = SoftwareSecureArea()
        let issuerKey = try await area.createKey(spec: KeySpec(secureArea: area.id, algorithm: .es256))
        let mock = MockIssuer(area: area, issuerKey: issuerKey, now: now)
        await mock.setCredentialIdentifiers(["pid-dataset-1", "pid-dataset-2"])
        let keys = try await makeKeys(area)
        let client = Openid4VciClient(http: mock, rng: TestRng(), clock: { self.now })

        let offer = try CredentialOffer.parse(mock.credentialOfferJson)
        let response = try await client.issueWithPreAuthorizedCode(offer: offer, configurationId: "eu.europa.ec.eudi.pid.1", keys: keys, txCode: "1234")

        XCTAssertEqual(1, response.credentials.count, "the credential is issued for the chosen dataset")
        let seenId = await mock.seenCredentialIdentifier
        let seenCfg = await mock.seenConfigurationId
        XCTAssertEqual("pid-dataset-1", seenId, "the request identifies the dataset by the first credential_identifier")
        XCTAssertNil(seenCfg, "credential_configuration_id MUST NOT be sent alongside a credential_identifier")
    }

    func testRequestsWithConfigurationIdWhenTokenBindsNoIdentifiers() async throws {
        // No authorization_details in the token response (e.g. scope-based authorization) → configuration id.
        let area = SoftwareSecureArea()
        let issuerKey = try await area.createKey(spec: KeySpec(secureArea: area.id, algorithm: .es256))
        let mock = MockIssuer(area: area, issuerKey: issuerKey, now: now)
        let keys = try await makeKeys(area)
        let client = Openid4VciClient(http: mock, rng: TestRng(), clock: { self.now })

        let offer = try CredentialOffer.parse(mock.credentialOfferJson)
        _ = try await client.issueWithPreAuthorizedCode(offer: offer, configurationId: "eu.europa.ec.eudi.pid.1", keys: keys, txCode: "1234")

        let seenCfg = await mock.seenConfigurationId
        let seenId = await mock.seenCredentialIdentifier
        XCTAssertEqual("eu.europa.ec.eudi.pid.1", seenCfg)
        XCTAssertNil(seenId)
    }
}
