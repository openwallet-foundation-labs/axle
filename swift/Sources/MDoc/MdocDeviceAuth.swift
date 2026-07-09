import CborCose
import Crypto
import Foundation

/// ISO 18013-5 §9.1.3.5 device-authentication form, chosen per credential (proximity and OpenID4VP alike).
public enum MdocDeviceAuthMode: Sendable {
    /// `deviceSignature` — an ECDSA signature any third party can verify.
    case signature

    /// `deviceMac` — an HMAC only the reader/verifier can check, since the `EMacKey` comes from a
    /// DeviceKey/EReaderKey ECDH. Non-transferable: the verifier cannot prove to anyone else that the
    /// mdoc answered. Requires a key-agreement `DeviceKey` and, in OpenID4VP, an encryption-enabled request.
    case mac
}

/// ECDH key agreement with the mdoc's `DeviceKey` for `deviceMac` (ISO 18013-5 §9.1.3.5). The private
/// half never leaves the secure area, so the caller supplies this over its `SecureArea` port; it returns
/// the raw shared secret `Zab` with the reader's/verifier's ephemeral public key.
public typealias MdocKeyAgreement = @Sendable (EcPublicKey) async throws -> [UInt8]

/// `deviceMac` key derivation and the OpenID4VP algorithm-identifier mapping (shared by proximity and OID4VP).
public enum MdocDeviceAuth {

    /// ISO 18013-5 §9.1.3.5 `EMacKey`: HKDF-SHA256 over the ECDH secret `sharedSecret`, salted by the
    /// SessionTranscript, info `"EMacKey"`, 32 bytes. The salt is `SHA-256(SessionTranscriptBytes)` where
    /// `SessionTranscriptBytes = #6.24(bstr .cbor SessionTranscript)` (§9.1.1.4).
    public static func emacKey(sharedSecret: [UInt8], sessionTranscript: Cbor) throws -> [UInt8] {
        let stBytes = try CborEncoder.encode(sessionTranscript)
        let salt = Data(SHA256.hash(data: Data(try CborEncoder.encode(.tagged(24, .bytes(stBytes))))))
        let key = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: Data(sharedSecret)),
            salt: salt, info: Data("EMacKey".utf8), outputByteCount: 32)
        return key.withUnsafeBytes { [UInt8]($0) }
    }

    /// OpenID4VP 1.0 Appendix B.2.2 Table 2: the COSE algorithm identifier for `HMAC 256/256` with the
    /// `EMacKey` established via ECDH on `curve` — what a verifier lists in `deviceauth_alg_values` to
    /// request `deviceMac`. Private-use identifiers pending IANA registration.
    public static func macAlgForCurve(_ curve: EcCurve) -> Int64 {
        switch curve {
        case .p256: return -65537
        case .p384: return -65538
        case .p521: return -65539
        }
    }
}
