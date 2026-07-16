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
                        validUntil: String = "2027-01-01T00:00:00Z", digestAlgorithm: String = "SHA-256") async throws -> [UInt8] {
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
            validUntil: MsoCodec.isoFormatter.date(from: validUntil)!,
            digestAlgorithm: digestAlgorithm
        )
    }

    func testVerifiesSha384AndSha512Digests() async throws {
        // ISO 18013-5 §9.1.2.5: readers must support SHA-384 and SHA-512, not only SHA-256.
        for alg in ["SHA-384", "SHA-512"] {
            let area = SoftwareSecureArea()
            let issuerKey = try await area.createKey(spec: KeySpec(secureArea: area.id, algorithm: .es256))
            let deviceKey = try await area.createKey(spec: KeySpec(secureArea: area.id, algorithm: .es256)).publicKey
            var bytes = try await issued(area: area, issuerKey: issuerKey, deviceKey: deviceKey, digestAlgorithm: alg)

            let verified = try await MdocVerifier(trust: TestTrust(expected: issuerKey.publicKey), now: { [now] in now }).verify(try IssuerSigned.decode(bytes))
            XCTAssertEqual(.text("Han"), verified.elements[namespace]?["family_name"], "\(alg) digests verify")
            // a tampered element still fails under the stronger digest
            let idx = indexOf(bytes, [UInt8]("Jongho".utf8))!
            bytes[idx] = UInt8(ascii: "X")
            let verifier = MdocVerifier(trust: TestTrust(expected: issuerKey.publicKey), now: { [now] in now })
            do { _ = try await verifier.verify(try IssuerSigned.decode(bytes)); XCTFail("tamper must fail under \(alg)") } catch is MdocError {}
        }
    }

    func testUnsupportedDigestAlgorithmRejected() async throws {
        let area = SoftwareSecureArea()
        let issuerKey = try await area.createKey(spec: KeySpec(secureArea: area.id, algorithm: .es256))
        let deviceKey = try await area.createKey(spec: KeySpec(secureArea: area.id, algorithm: .es256)).publicKey
        let bytes = try await issued(area: area, issuerKey: issuerKey, deviceKey: deviceKey, digestAlgorithm: "SHA-1")

        let verifier = MdocVerifier(trust: TestTrust(expected: issuerKey.publicKey), now: { [now] in now })
        do { _ = try await verifier.verify(try IssuerSigned.decode(bytes)); XCTFail("should reject SHA-1") } catch is MdocError {}
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

    func testParsesFractionalSecondValidityDates() async throws {
        // Issuers commonly emit MSO validityInfo tdates with fractional seconds (JS `Date().toISOString()` →
        // `…​.SSSZ`). The MSO must still parse — regression: iOS mdoc showed every credential "not verified"
        // because `ISO8601DateFormatter([.withInternetDateTime])` rejects fractional seconds (Android accepted them).
        let area = SoftwareSecureArea()
        let deviceKey = try await area.createKey(spec: KeySpec(secureArea: area.id, algorithm: .es256)).publicKey
        func tdate(_ s: String) -> Cbor { .tagged(TAG_TDATE, .text(s)) }
        let mso = Cbor.map([
            (.text("version"), .text("1.0")),
            (.text("digestAlgorithm"), .text("SHA-256")),
            (.text("valueDigests"), .map([(.text(namespace), .map([]))])),
            (.text("deviceKeyInfo"), .map([(.text("deviceKey"), CoseKey.encode(deviceKey))])),
            (.text("docType"), .text(docType)),
            (.text("validityInfo"), .map([
                (.text("signed"), tdate("2026-01-01T00:06:11.123Z")),
                (.text("validFrom"), tdate("2026-01-01T00:06:11.123Z")),
                (.text("validUntil"), tdate("2035-12-31T23:59:59.999Z")),
            ])),
        ])
        let parsed = try MsoCodec.parse(try CborEncoder.encode(mso))
        XCTAssertEqual(MsoCodec.isoFractionalFormatter.date(from: "2035-12-31T23:59:59.999Z"), parsed.validUntil)
        // whole-second tdates must still parse (the fallback must not have replaced the base formatter)
        XCTAssertNotNil(MsoCodec.isoFormatter.date(from: "2026-01-01T00:00:00Z"))
    }

    private func indexOf(_ haystack: [UInt8], _ needle: [UInt8]) -> Int? {
        guard needle.count <= haystack.count else { return nil }
        for i in 0...(haystack.count - needle.count) where Array(haystack[i..<i + needle.count]) == needle { return i }
        return nil
    }
}
