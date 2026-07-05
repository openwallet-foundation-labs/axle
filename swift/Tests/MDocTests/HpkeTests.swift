import CborCose
import XCTest
@testable import MDoc

/// Verifies the HPKE seal against RFC 9180 Appendix A.3 (DHKEM-P256-HKDF-SHA256 / HKDF-SHA256 / AES-128-GCM, base mode).
final class HpkeTests: XCTestCase {
    private func hex(_ s: String) -> [UInt8] {
        var out = [UInt8](), idx = s.startIndex
        while idx < s.endIndex {
            let next = s.index(idx, offsetBy: 2)
            out.append(UInt8(s[idx..<next], radix: 16)!)
            idx = next
        }
        return out
    }
    private func hexStr(_ b: [UInt8]) -> String { b.map { String(format: "%02x", $0) }.joined() }

    func testRfc9180AppendixA3BaseSeq0() throws {
        let info = hex("4f6465206f6e2061204772656369616e2055726e")
        let skEm = hex("4995788ef4b9d6132b249ce59a77281493eb39af373d236a1fe415cb0c2d7beb")
        let pkEm = hex("04a92719c6195d5085104f469a8b9814d5838ff72b60501e2c4466e5e67b325ac98536d7b61a1af4b78e5b7f951c0900be863c403ce65c9bfcb9382657222d18c4")
        let pkRm = hex("04fe8c19ce0905191ebc298a9245792531f26f0cece2460639e8bc39cb7f706a826a779b4cf969b8a0e539c7f62fb3d30ad6aa8f80e30f1d128aafd68a2ce72ea0")
        let aad = hex("436f756e742d30")
        let pt = hex("4265617574792069732074727574682c20747275746820626561757479")
        let expectedCt = "5ad590bb8baa577f8619db35a36311226a896e7342a6d836d8b7bcd2f20b6c7f9076ac232e3ab2523f39513434"

        let recipient = EcPublicKey(curve: .p256, x: Array(pkRm[1..<33]), y: Array(pkRm[33..<65]))
        let ephemeral = try Hpke.Ephemeral.of(scalar: skEm, publicUncompressed: pkEm)
        let sealed = try Hpke.sealBaseP256(recipient: recipient, info: info, aad: aad, plaintext: pt, ephemeral: ephemeral)

        XCTAssertEqual(hexStr(pkEm), hexStr(sealed.enc), "enc must equal pkEm")
        XCTAssertEqual(expectedCt, hexStr(sealed.ciphertext), "ciphertext must match RFC 9180 A.3 seq0")
    }
}
