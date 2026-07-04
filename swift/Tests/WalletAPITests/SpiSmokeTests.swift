import XCTest
@testable import WalletAPI

final class SpiSmokeTests: XCTestCase {

    func testKeySpecDefaultsMatchContract() {
        let spec = KeySpec()
        XCTAssertEqual(SecureAreaId.default, spec.secureArea)
        XCTAssertEqual(SigningAlgorithm.es256, spec.algorithm)
        XCTAssertEqual(UserAuthPolicy.notRequired, spec.userAuthentication)
    }

    func testCredentialPolicyDefaultsMatchContract() {
        let policy = CredentialPolicy()
        XCTAssertEqual(1, policy.batchSize)
        XCTAssertEqual(CredentialPolicy(batchSize: 1, use: .rotate), policy)
    }

    func testRuntimeDefaultsWork() {
        XCTAssertLessThanOrEqual(SystemClock().now().timeIntervalSinceNow.magnitude, 5)
        let bytes = SystemRng().nextBytes(16)
        XCTAssertEqual(16, bytes.count)
        XCTAssertTrue(bytes.contains { $0 != 0 }, "16 random bytes should not be all zero")
    }
}
