import CborCose
import Foundation
import MDoc
import TrustList
import WalletAPI
import XCTest
@testable import Trust

/// Fixture-driven interop check: verifies mdocs produced by the REAL issuer-be code path (generated via
/// `ecosystem` tooling into a JSON file) with the exact verifier + chain-validation stack the iOS wallet
/// runs at issuance review. Env-gated: set `EUDI_MDOC_FIXTURES=/path/to/mdoc-fixtures.json`.
final class LiveIssuerFixtureTests: XCTestCase {
    struct Fixture: Decodable {
        let id: String
        let doctype: String
        let signer: String
        let issuerSignedB64: String
        let caDerB64: String
    }

    func testIssuerFixturesVerifyWithSwiftVerifier() async throws {
        guard let path = ProcessInfo.processInfo.environment["EUDI_MDOC_FIXTURES"] else {
            throw XCTSkip("EUDI_MDOC_FIXTURES not set")
        }
        let fixtures = try JSONDecoder().decode([Fixture].self, from: Data(contentsOf: URL(fileURLWithPath: path)))
        var failures: [String] = []
        for f in fixtures {
            do {
                guard let raw = Data(base64Encoded: f.issuerSignedB64), let ca = Data(base64Encoded: f.caDerB64) else {
                    throw TrustError("fixture base64 invalid")
                }
                let trust = X5cMdocIssuerTrust(validator: X509ChainValidator(anchors: try TrustAnchors.ofDer([[UInt8](ca)])))
                let v = try await MdocVerifier(trust: trust).verify(try IssuerSigned.decode([UInt8](raw)))
                print("✅ \(f.id): docType=\(v.docType) namespaces=\(v.elements.mapValues(\.count)) validFrom=\(v.validFrom) validUntil=\(v.validUntil)")
            } catch {
                failures.append("\(f.id): \(error)")
                print("❌ \(f.id): \(error)")
            }
        }
        XCTAssertTrue(failures.isEmpty, failures.joined(separator: " | "))
    }

    /// Reproduces the demo wallet's boot-time anchor fetch (AppleTrust): both sandbox trusted lists must
    /// verify against the pinned Scheme Operator and yield at least one CA anchor.
    func testLiveTrustedListsYieldAnchors() async throws {
        guard ProcessInfo.processInfo.environment["EUDI_MDOC_FIXTURES"] != nil else {
            throw XCTSkip("EUDI_MDOC_FIXTURES not set (live-network test rides the same gate)")
        }
        let http = CurlTransport()
        let base = "https://trusted-list.vercel.app/tl"
        let soResp = try await http.execute(HttpRequest(method: .get, url: "\(base)/scheme-operator.pem"))
        guard soResp.status == 200, let soDer = Self.pemToDer(String(decoding: soResp.body, as: UTF8.self)) else {
            return XCTFail("scheme-operator fetch failed: HTTP \(soResp.status)")
        }
        let client = TrustedListClient(http: http)
        for slug in ["pid-issuers", "attestation-issuers"] {
            do {
                let anchors = try await client.fetchCACerts(url: "\(base)/\(slug).jades.json", schemeOperatorAnchorDer: soDer)
                print("✅ trusted list '\(slug)': \(anchors.count) anchor(s)")
                XCTAssertFalse(anchors.isEmpty, "'\(slug)' returned no anchors")
            } catch {
                XCTFail("❌ trusted list '\(slug)': \(error)")
            }
        }
    }

    private static func pemToDer(_ pem: String) -> [UInt8]? {
        let b64 = pem
            .replacingOccurrences(of: "-----BEGIN CERTIFICATE-----", with: "")
            .replacingOccurrences(of: "-----END CERTIFICATE-----", with: "")
            .components(separatedBy: .whitespacesAndNewlines).joined()
        return Data(base64Encoded: b64).map { [UInt8]($0) }
    }
}

/// Minimal GET-only transport backed by the curl CLI — avoids FoundationNetworking flakiness on Linux CI.
private struct CurlTransport: HttpTransport {
    func execute(_ request: HttpRequest) async throws -> HttpResponse {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/bin/curl")
        p.arguments = ["-sS", "-w", "\n%{http_code}", request.url]
        let out = Pipe()
        p.standardOutput = out
        try p.run()
        let data = out.fileHandleForReading.readDataToEndOfFile()
        p.waitUntilExit()
        guard let nl = data.lastIndex(of: UInt8(ascii: "\n")) else { throw TrustError("curl produced no output") }
        let status = Int(String(decoding: data[data.index(after: nl)...], as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)) ?? 0
        return HttpResponse(status: status, headers: [], body: [UInt8](data[..<nl]))
    }
}
