import CborCose
import Foundation
import WalletAPI
import WalletTestKit
import XCTest
@testable import MDoc

final class MdocVerifierTests: XCTestCase {

    private let docType = "org.iso.18013.5.1.mDL"
    private let namespace = "org.iso.18013.5.1"
    private let now = MsoCodec.isoFormatter.date(from: "2026-06-01T00:00:00Z")!

    private struct TestTrust: MdocIssuerTrust {
        let expected: EcPublicKey // unit-level: chain validation is covered by the Trust module
        func issuerKey(x5chain: [[UInt8]]) async throws -> EcPublicKey { expected }
    }

    private func issued(area: SoftwareSecureArea, issuerKey: KeyInfo, deviceKey: EcPublicKey,
                        validUntil: String = "2027-01-01T00:00:00Z") async throws -> [UInt8] {
        try await MdocTestIssuer.issue(
            area: area, issuerKey: issuerKey, deviceKey: deviceKey,
            docType: docType, namespace: namespace,
            elements: [
                ("family_name", .text("Han")),
                ("given_name", .text("Jongho")),
                ("age_over_18", .bool(true)),
            ],
            x5chain: [[0x30, 0x01, 0x02]], // placeholder DER; resolver returns the known key
            signed: MsoCodec.isoFormatter.date(from: "2026-01-01T00:00:00Z")!,
            validFrom: MsoCodec.isoFormatter.date(from: "2026-01-01T00:00:00Z")!,
            validUntil: MsoCodec.isoFormatter.date(from: validUntil)!
        )
    }

    func testParseRoundtrip() async throws {
        let area = SoftwareSecureArea()
        let issuerKey = try await area.createKey(spec: KeySpec(secureArea: area.id, algorithm: .es256))
        let deviceKey = try await area.createKey(spec: KeySpec(secureArea: area.id, algorithm: .es256)).publicKey
        let bytes = try await issued(area: area, issuerKey: issuerKey, deviceKey: deviceKey)

        let parsed = try IssuerSigned.decode(bytes)
        XCTAssertEqual(3, parsed.nameSpaces.first!.1.count)
        XCTAssertEqual("family_name", parsed.nameSpaces.first!.1[0].item.elementIdentifier)
        XCTAssertEqual([0x30, 0x01, 0x02], parsed.issuerCertChain!.first!)
    }

    func testVerifiesAndDisclosesElements() async throws {
        let area = SoftwareSecureArea()
        let issuerKey = try await area.createKey(spec: KeySpec(secureArea: area.id, algorithm: .es256))
        let deviceKey = try await area.createKey(spec: KeySpec(secureArea: area.id, algorithm: .es256)).publicKey
        let bytes = try await issued(area: area, issuerKey: issuerKey, deviceKey: deviceKey)

        let verified = try await MdocVerifier(trust: TestTrust(expected: issuerKey.publicKey), now: { [now] in now }).verify(try IssuerSigned.decode(bytes))
        XCTAssertEqual(docType, verified.docType)
        XCTAssertEqual(.text("Han"), verified.elements[namespace]?["family_name"])
        XCTAssertEqual(.text("Jongho"), verified.elements[namespace]?["given_name"])
        XCTAssertEqual(.bool(true), verified.elements[namespace]?["age_over_18"])
        XCTAssertEqual(deviceKey.x, verified.deviceKey.x) // holder binding preserved
    }

    func testWrongIssuerKeyRejected() async throws {
        let area = SoftwareSecureArea()
        let issuerKey = try await area.createKey(spec: KeySpec(secureArea: area.id, algorithm: .es256))
        let wrongKey = try await area.createKey(spec: KeySpec(secureArea: area.id, algorithm: .es256))
        let deviceKey = try await area.createKey(spec: KeySpec(secureArea: area.id, algorithm: .es256)).publicKey
        let bytes = try await issued(area: area, issuerKey: issuerKey, deviceKey: deviceKey)

        let verifier = MdocVerifier(trust: TestTrust(expected: wrongKey.publicKey), now: { [now] in now })
        do { _ = try await verifier.verify(try IssuerSigned.decode(bytes)); XCTFail("should reject") } catch is MdocError {}
    }

    func testTamperedElementRejected() async throws {
        let area = SoftwareSecureArea()
        let issuerKey = try await area.createKey(spec: KeySpec(secureArea: area.id, algorithm: .es256))
        let deviceKey = try await area.createKey(spec: KeySpec(secureArea: area.id, algorithm: .es256)).publicKey
        var bytes = try await issued(area: area, issuerKey: issuerKey, deviceKey: deviceKey)

        let needle = [UInt8]("Jongho".utf8)
        let idx = indexOf(bytes, needle)!
        bytes[idx] = UInt8(ascii: "X")
        let verifier = MdocVerifier(trust: TestTrust(expected: issuerKey.publicKey), now: { [now] in now })
        do { _ = try await verifier.verify(try IssuerSigned.decode(bytes)); XCTFail("should reject tampered") } catch is MdocError {}
    }

    func testExpiredMdocRejected() async throws {
        let area = SoftwareSecureArea()
        let issuerKey = try await area.createKey(spec: KeySpec(secureArea: area.id, algorithm: .es256))
        let deviceKey = try await area.createKey(spec: KeySpec(secureArea: area.id, algorithm: .es256)).publicKey
        let bytes = try await issued(area: area, issuerKey: issuerKey, deviceKey: deviceKey, validUntil: "2026-05-01T00:00:00Z")

        let verifier = MdocVerifier(trust: TestTrust(expected: issuerKey.publicKey), now: { [now] in now })
        do { _ = try await verifier.verify(try IssuerSigned.decode(bytes)); XCTFail("should reject expired") } catch is MdocError {}
    }

    private func indexOf(_ haystack: [UInt8], _ needle: [UInt8]) -> Int? {
        guard needle.count <= haystack.count else { return nil }
        for i in 0...(haystack.count - needle.count) where Array(haystack[i..<i + needle.count]) == needle { return i }
        return nil
    }
}
