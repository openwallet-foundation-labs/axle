import Foundation
import SdJwt
import WalletAPI
import WalletTestKit
import XCTest
@testable import OpenID4VCI

/// HAIP tail: deferred issuance (§9) and issuance notifications (§10).
final class DeferredNotificationTests: XCTestCase {

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

    func testDeferredIssuancePollsUntilReady() async throws {
        let area = SoftwareSecureArea()
        let issuerKey = try await area.createKey(spec: KeySpec(secureArea: area.id, algorithm: .es256))
        let mock = MockIssuer(area: area, issuerKey: issuerKey, now: now)
        await mock.setDeferMode(true)
        let keys = try await makeKeys(area)
        let client = Openid4VciClient(http: mock, rng: TestRng(), clock: { self.now })

        let offer = try CredentialOffer.parse(mock.credentialOfferJson)
        let deferred = try await client.issueWithPreAuthorizedCode(offer: offer, configurationId: "eu.europa.ec.eudi.pid.1", keys: keys, txCode: "1234")

        XCTAssertTrue(deferred.isDeferred, "issuer deferred issuance")
        XCTAssertEqual(0, deferred.credentials.count)
        XCTAssertNotNil(deferred.transactionId)
        XCTAssertEqual(300, deferred.interval, "§8.3 interval is parsed")

        // first poll: §9.2 still-deferred — a fresh CredentialResponse that is again isDeferred, not an error.
        let stillDeferred = try await client.fetchDeferredCredential(deferred, keys: keys)
        XCTAssertTrue(stillDeferred.isDeferred, "issuer re-deferred")
        XCTAssertEqual(42, stillDeferred.interval)
        // second poll: credential is ready
        let ready = try await client.fetchDeferredCredential(deferred, keys: keys)
        XCTAssertEqual(1, ready.credentials.count)
    }

    func testIssuanceNotificationSent() async throws {
        let area = SoftwareSecureArea()
        let issuerKey = try await area.createKey(spec: KeySpec(secureArea: area.id, algorithm: .es256))
        let mock = MockIssuer(area: area, issuerKey: issuerKey, now: now)
        let keys = try await makeKeys(area)
        let client = Openid4VciClient(http: mock, rng: TestRng(), clock: { self.now })

        let offer = try CredentialOffer.parse(mock.credentialOfferJson)
        let response = try await client.issueWithPreAuthorizedCode(offer: offer, configurationId: "eu.europa.ec.eudi.pid.1", keys: keys, txCode: "1234")
        XCTAssertEqual(1, response.credentials.count)
        XCTAssertEqual("n-1", response.notificationId)

        try await client.sendNotification(response, event: .credentialAccepted, keys: keys)
        let seen = await mock.seenNotification
        XCTAssertEqual("n-1", seen?.0)
        XCTAssertEqual("credential_accepted", seen?.1)
    }
}
