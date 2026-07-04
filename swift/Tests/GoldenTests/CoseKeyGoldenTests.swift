import CborCose
import SdJwt
import XCTest

/// Cross-language golden vectors for COSE_Key EC2 encoding (RFC 9052 §7) — shared with Kotlin.
final class CoseKeyGoldenTests: XCTestCase {

    func testCoseKeyEncodingMatchesGolden() throws {
        let root = try GoldenVectors.load("cose/cose-key.json")
        guard case let .obj(o) = root, case let .arr(vectors)? = o.first(where: { $0.0 == "vectors" })?.1 else {
            return XCTFail("bad vectors file")
        }
        for v in vectors {
            guard case let .obj(fields) = v else { return XCTFail("bad vector") }
            func s(_ k: String) -> String? { if case let .str(x)? = fields.first(where: { $0.0 == k })?.1 { return x }; return nil }
            let name = s("name")!
            let curve: EcCurve
            switch s("crv")! {
            case "P-256": curve = .p256
            case "P-384": curve = .p384
            case "P-521": curve = .p521
            default: return XCTFail("unknown curve")
            }
            let key = EcPublicKey(curve: curve, x: GoldenVectors.hexToBytes(s("x")!), y: GoldenVectors.hexToBytes(s("y")!))
            let hex = GoldenVectors.toHex(try CborEncoder.encode(CoseKey.encode(key)))
            XCTAssertEqual(s("hex")!, hex, "cose-key '\(name)'")
        }
    }
}
