import XCTest
import Foundation
import Crypto
@testable import CborCose

/// Runs the official cose-wg/Examples sign1-tests corpus (vectors/cose/).
final class CoseSign1Tests: XCTestCase {

    private struct Vector {
        let publicKey: EcPublicKey
        let d: [UInt8]
        let external: [UInt8]
        let cborHex: String
        let toBeSignHex: String?

        init(_ name: String) throws {
            var url = URL(fileURLWithPath: #filePath)
            for _ in 0..<4 { url.deleteLastPathComponent() }
            url.appendPathComponent("vectors/cose/\(name).json")
            let json = try JSONSerialization.jsonObject(with: Data(contentsOf: url)) as! [String: Any]
            let input = json["input"] as! [String: Any]
            let sign0 = input["sign0"] as! [String: Any]
            let key = sign0["key"] as! [String: String]
            publicKey = EcPublicKey(curve: .p256, x: b64url(key["x"]!), y: b64url(key["y"]!))
            d = b64url(key["d"]!)
            external = (sign0["external"] as? String).map(hexToBytes) ?? []
            cborHex = (json["output"] as! [String: Any])["cbor"] as! String
            toBeSignHex = (json["intermediates"] as? [String: Any])?["ToBeSign_hex"] as? String
        }
    }

    private struct SoftwareSigner: CoseSigner {
        let algorithm: CoseAlgorithm = .es256
        let d: Data // raw key bytes: P256.Signing.PrivateKey itself is not Sendable

        func sign(_ toBeSigned: [UInt8]) async throws -> [UInt8] {
            let key = try P256.Signing.PrivateKey(rawRepresentation: d)
            return [UInt8](try key.signature(for: Data(toBeSigned)).rawRepresentation)
        }
    }

    func testPassVectors() async throws {
        for name in ["sign-pass-01", "sign-pass-02", "sign-pass-03"] {
            let v = try Vector(name)
            let bytes = hexToBytes(v.cborHex)
            let tagged = bytes[0] == 0xD2

            let s1 = try CoseSign1.decode(bytes)

            // 1. Sig_structure must match the official intermediate byte-for-byte
            let toBeSigned = try CoseSign1.sigStructure(
                protectedBytes: s1.protectedBytes, externalAad: v.external, payload: s1.payload!
            )
            XCTAssertEqual(v.toBeSignHex?.lowercased(), toHex(toBeSigned), "\(name): Sig_structure")

            // 2. official signature verifies
            XCTAssertTrue(s1.verify(publicKey: v.publicKey, externalAad: v.external), "\(name): verify")

            // 3. re-encode is byte-identical (vectors are deterministically encoded)
            XCTAssertEqual(v.cborHex.lowercased(), toHex(try s1.encode(tagged: tagged)), "\(name): re-encode")

            // 4. tampered payload fails
            var tampered = s1.payload!
            tampered[0] &+= 1
            XCTAssertFalse(
                CoseSign1(
                    protectedBytes: s1.protectedBytes,
                    unprotected: s1.unprotected,
                    payload: tampered,
                    signature: s1.signature
                ).verify(publicKey: v.publicKey, externalAad: v.external),
                "\(name): tamper"
            )

            // 5. our own signature (same headers/payload, software key) verifies
            let signer = SoftwareSigner(d: Data(v.d))
            let signed = try await CoseSign1.sign(
                protected: try s1.protectedHeaders(),
                unprotected: s1.unprotected,
                payload: s1.payload,
                externalAad: v.external,
                signer: signer
            )
            XCTAssertTrue(signed.verify(publicKey: v.publicKey, externalAad: v.external), "\(name): sign roundtrip")
        }
    }

    func testFailVectorChangedContent() throws {
        let v = try Vector("sign-fail-02")
        let s1 = try CoseSign1.decode(hexToBytes(v.cborHex))
        XCTAssertFalse(s1.verify(publicKey: v.publicKey, externalAad: v.external))
    }

    func testHeaderAccessors() throws {
        let v = try Vector("sign-pass-01")
        let s1 = try CoseSign1.decode(hexToBytes(v.cborHex))
        // pass-01: protected is h'A0' (empty map), alg + kid live in unprotected
        XCTAssertTrue(try s1.protectedHeaders().isEmpty)
        XCTAssertEqual(.es256, s1.unprotected.algorithm)
        XCTAssertEqual([UInt8]("11".utf8), s1.unprotected.kid)
        XCTAssertEqual(.es256, s1.algorithm)
    }
}

func b64url(_ s: String) -> [UInt8] {
    var t = s.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
    while t.count % 4 != 0 { t += "=" }
    return [UInt8](Data(base64Encoded: t)!)
}
