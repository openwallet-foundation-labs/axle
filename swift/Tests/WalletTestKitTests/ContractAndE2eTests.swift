import CborCose
import WalletAPI
import XCTest
@testable import WalletTestKit

final class ContractAndE2eTests: XCTestCase {

    func testSoftwareSecureAreaPassesPortContract() async throws {
        try await SecureAreaContract.verify(SoftwareSecureArea())
    }

    func testInMemoryStorageDriverPassesPortContract() async throws {
        try await StorageDriverContract.verify(InMemoryStorageDriver())
    }

    /// M1 완료 기준 E2E: 키 생성 → COSE_Sign1 서명(포트 경유) → 인코드/디코드 → 검증.
    /// 프로덕션과 동일 경로 — 개인키는 SecureArea 밖으로 나오지 않는다.
    func testCreateSignEncodeDecodeVerify() async throws {
        let area = SoftwareSecureArea()
        let payload = [UInt8]("hello eudi wallet sdk".utf8)

        for algorithm in [SigningAlgorithm.es256, .es384, .es512] {
            let key = try await area.createKey(spec: KeySpec(secureArea: area.id, algorithm: algorithm))

            let signed = try await CoseSign1.sign(
                protected: CoseHeaders.of(algorithm: algorithm.coseAlgorithm),
                payload: payload,
                signer: SecureAreaCoseSigner(area: area, key: key.handle, algorithm: algorithm)
            )

            let decoded = try CoseSign1.decode(try signed.encode())
            XCTAssertTrue(decoded.verify(publicKey: key.publicKey), "\(algorithm): decoded message must verify")

            let tampered = CoseSign1(
                protectedBytes: decoded.protectedBytes,
                unprotected: decoded.unprotected,
                payload: [UInt8]("tampered payload".utf8),
                signature: decoded.signature
            )
            XCTAssertFalse(tampered.verify(publicKey: key.publicKey), "\(algorithm): tampered payload must fail")
        }
    }
}
