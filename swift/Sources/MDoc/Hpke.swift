import CborCose
import Crypto
import Foundation

/// HPKE (RFC 9180) — base mode, cipher suite DHKEM(P-256, HKDF-SHA256) / HKDF-SHA256 / AES-128-GCM.
/// The suite the ISO/IEC 18013-7:2025 Annex C Digital Credentials API uses to encrypt the mdoc
/// `DeviceResponse` to the verifier's ephemeral `recipientPublicKey`. Single-shot sealing only.
public enum Hpke {
    private static let kemId = 0x0010, kdfId = 0x0001, aeadId = 0x0001
    private static let nSecret = 32, nk = 16, nn = 12, nh = 32

    /// The `enc` (encapsulated ephemeral public key, uncompressed) and the AEAD `ciphertext` (incl. tag).
    public struct Sealed { public let enc: [UInt8]; public let ciphertext: [UInt8] }

    /// An HPKE ephemeral P-256 key pair; random in production, injectable for RFC test vectors.
    public struct Ephemeral {
        let privateKey: P256.KeyAgreement.PrivateKey
        let publicUncompressed: [UInt8] // 0x04 || X || Y
        public static func random() -> Ephemeral {
            let k = P256.KeyAgreement.PrivateKey()
            return Ephemeral(privateKey: k, publicUncompressed: [UInt8](k.publicKey.x963Representation))
        }
        static func of(scalar: [UInt8], publicUncompressed: [UInt8]) throws -> Ephemeral {
            Ephemeral(privateKey: try P256.KeyAgreement.PrivateKey(rawRepresentation: Data(scalar)), publicUncompressed: publicUncompressed)
        }
    }

    /// Seals `plaintext` to `recipient` with the given HPKE `info`/`aad`. `ephemeral` is injectable for test vectors.
    public static func sealBaseP256(recipient: EcPublicKey, info: [UInt8], aad: [UInt8], plaintext: [UInt8],
                                    ephemeral: Ephemeral = .random()) throws -> Sealed {
        let recipientKa = try P256.KeyAgreement.PublicKey(x963Representation: Data([0x04] + pad(recipient.x) + pad(recipient.y)))
        let dh = try ephemeral.privateKey.sharedSecretFromKeyAgreement(with: recipientKa).withUnsafeBytes { [UInt8]($0) }
        let enc = ephemeral.publicUncompressed
        let kemContext = enc + [UInt8](recipientKa.x963Representation) // enc || pkRm (uncompressed)

        let sharedSecret = extractAndExpand(kemSuiteId(), dh, kemContext, nSecret)
        let pskIdHash = labeledExtract(hpkeSuiteId(), nil, "psk_id_hash", [])
        let infoHash = labeledExtract(hpkeSuiteId(), nil, "info_hash", info)
        let ksContext = [0] + pskIdHash + infoHash // base mode
        let secret = labeledExtract(hpkeSuiteId(), sharedSecret, "secret", [])
        let key = labeledExpand(hpkeSuiteId(), secret, "key", ksContext, nk)
        let baseNonce = labeledExpand(hpkeSuiteId(), secret, "base_nonce", ksContext, nn)

        // Single-shot: sequence number 0, so the per-message nonce equals base_nonce.
        let box = try AES.GCM.seal(Data(plaintext), using: SymmetricKey(data: Data(key)),
                                   nonce: try AES.GCM.Nonce(data: Data(baseNonce)), authenticating: Data(aad))
        return Sealed(enc: enc, ciphertext: [UInt8](box.ciphertext) + [UInt8](box.tag))
    }

    // MARK: - RFC 9180 §4 labeled KDF

    private static func kemSuiteId() -> [UInt8] { [UInt8]("KEM".utf8) + i2osp(kemId, 2) }
    private static func hpkeSuiteId() -> [UInt8] { [UInt8]("HPKE".utf8) + i2osp(kemId, 2) + i2osp(kdfId, 2) + i2osp(aeadId, 2) }

    private static func labeledExtract(_ suiteId: [UInt8], _ salt: [UInt8]?, _ label: String, _ ikm: [UInt8]) -> [UInt8] {
        hkdfExtract(salt, [UInt8]("HPKE-v1".utf8) + suiteId + [UInt8](label.utf8) + ikm)
    }

    private static func labeledExpand(_ suiteId: [UInt8], _ prk: [UInt8], _ label: String, _ info: [UInt8], _ length: Int) -> [UInt8] {
        hkdfExpand(prk, i2osp(length, 2) + [UInt8]("HPKE-v1".utf8) + suiteId + [UInt8](label.utf8) + info, length)
    }

    private static func extractAndExpand(_ suiteId: [UInt8], _ dh: [UInt8], _ kemContext: [UInt8], _ length: Int) -> [UInt8] {
        let eaePrk = labeledExtract(suiteId, nil, "eae_prk", dh)
        return labeledExpand(suiteId, eaePrk, "shared_secret", kemContext, length)
    }

    // MARK: - HKDF-SHA256 (RFC 5869)

    private static func hkdfExtract(_ salt: [UInt8]?, _ ikm: [UInt8]) -> [UInt8] { hmac(salt ?? [UInt8](repeating: 0, count: nh), ikm) }

    private static func hkdfExpand(_ prk: [UInt8], _ info: [UInt8], _ length: Int) -> [UInt8] {
        var out = [UInt8](), t = [UInt8](), i = 1
        while out.count < length {
            t = hmac(prk, t + info + [UInt8(i)])
            out += t
            i += 1
        }
        return Array(out.prefix(length))
    }

    private static func hmac(_ key: [UInt8], _ data: [UInt8]) -> [UInt8] {
        let k = SymmetricKey(data: key.isEmpty ? [UInt8](repeating: 0, count: nh) : key)
        return [UInt8](HMAC<SHA256>.authenticationCode(for: Data(data), using: k))
    }

    // MARK: - helpers

    private static func i2osp(_ value: Int, _ length: Int) -> [UInt8] {
        var out = [UInt8](repeating: 0, count: length), v = value
        for i in stride(from: length - 1, through: 0, by: -1) { out[i] = UInt8(v & 0xFF); v >>= 8 }
        return out
    }

    private static func pad(_ b: [UInt8]) -> [UInt8] {
        b.count >= 32 ? Array(b.suffix(32)) : [UInt8](repeating: 0, count: 32 - b.count) + b
    }
}
