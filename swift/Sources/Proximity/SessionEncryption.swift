import CborCose
import Crypto
import Foundation

public struct ProximityError: Error, CustomStringConvertible {
    public let description: String
    init(_ description: String) { self.description = description }
}

/// An ephemeral P-256 key pair for mdoc session establishment (EDeviceKey / EReaderKey).
public struct EphemeralKeyPair {
    private let privateKey: P256.KeyAgreement.PrivateKey

    public init() { privateKey = P256.KeyAgreement.PrivateKey() }

    public var publicKey: EcPublicKey {
        let raw = privateKey.publicKey.rawRepresentation // x || y
        return EcPublicKey(curve: .p256, x: [UInt8](raw.prefix(32)), y: [UInt8](raw.suffix(32)))
    }

    /// Raw ECDH shared secret (Zab) with the peer's ephemeral key.
    public func sharedSecret(_ peer: EcPublicKey) throws -> [UInt8] {
        let peerKey = try P256.KeyAgreement.PublicKey(rawRepresentation: Data(peer.x + peer.y))
        return try privateKey.sharedSecretFromKeyAgreement(with: peerKey).withUnsafeBytes { [UInt8]($0) }
    }
}

/// mdoc session encryption (ISO/IEC 18013-5 §9.1.1): derives `SKDevice`/`SKReader` from the ECDH
/// secret and the SessionTranscript via HKDF-SHA256, then encrypts each message with AES-256-GCM.
/// The 12-byte IV is an 8-byte per-direction identifier (`…01` mdoc, `…00` reader) plus a 4-byte
/// big-endian message counter starting at 1.
public final class SessionEncryption {
    private var sendKey: SymmetricKey?
    private let sendIdentifier: [UInt8]
    private var recvKey: SymmetricKey?
    private let recvIdentifier: [UInt8]
    private var sendCounter: UInt32 = 0
    private var recvCounter: UInt32 = 0

    private static let mdocIdentifier: [UInt8] = [0, 0, 0, 0, 0, 0, 0, 1]
    private static let readerIdentifier: [UInt8] = [0, 0, 0, 0, 0, 0, 0, 0]

    private init(sendKey: SymmetricKey, sendIdentifier: [UInt8], recvKey: SymmetricKey, recvIdentifier: [UInt8]) {
        self.sendKey = sendKey; self.sendIdentifier = sendIdentifier
        self.recvKey = recvKey; self.recvIdentifier = recvIdentifier
    }

    public func encrypt(_ plaintext: [UInt8]) throws -> [UInt8] {
        guard let sendKey else { throw ProximityError("session keys destroyed") }
        sendCounter += 1
        let box = try AES.GCM.seal(plaintext, using: sendKey, nonce: try AES.GCM.Nonce(data: iv(sendIdentifier, sendCounter)))
        return [UInt8](box.ciphertext) + [UInt8](box.tag)
    }

    public func decrypt(_ message: [UInt8]) throws -> [UInt8] {
        guard let recvKey else { throw ProximityError("session keys destroyed") }
        recvCounter += 1
        guard message.count >= 16 else { throw ProximityError("session message too short") }
        let box: AES.GCM.SealedBox
        do {
            box = try AES.GCM.SealedBox(nonce: try AES.GCM.Nonce(data: iv(recvIdentifier, recvCounter)),
                                        ciphertext: message.dropLast(16), tag: message.suffix(16))
            return [UInt8](try AES.GCM.open(box, using: recvKey))
        } catch {
            throw ProximityError("session message authentication failed")
        }
    }

    /// ISO 18013-5 §9.1.1.4: on session termination the session keys are destroyed. Drops `SKDevice` and
    /// `SKReader`; idempotent, and any further encrypt/decrypt then fails fast.
    public func destroy() {
        sendKey = nil
        recvKey = nil
    }

    /// Wallet (mdoc) side: sends with SKDevice, receives reader messages with SKReader.
    public static func forMdoc(ephemeral: EphemeralKeyPair, readerPublicKey: EcPublicKey, sessionTranscriptBytes: [UInt8]) throws -> SessionEncryption {
        let (skDevice, skReader) = try deriveKeys(try ephemeral.sharedSecret(readerPublicKey), sessionTranscriptBytes)
        return SessionEncryption(sendKey: skDevice, sendIdentifier: mdocIdentifier, recvKey: skReader, recvIdentifier: readerIdentifier)
    }

    /// Reader side: sends with SKReader, receives mdoc messages with SKDevice.
    public static func forReader(ephemeral: EphemeralKeyPair, devicePublicKey: EcPublicKey, sessionTranscriptBytes: [UInt8]) throws -> SessionEncryption {
        let (skDevice, skReader) = try deriveKeys(try ephemeral.sharedSecret(devicePublicKey), sessionTranscriptBytes)
        return SessionEncryption(sendKey: skReader, sendIdentifier: readerIdentifier, recvKey: skDevice, recvIdentifier: mdocIdentifier)
    }

    private static func deriveKeys(_ sharedSecret: [UInt8], _ sessionTranscriptBytes: [UInt8]) throws -> (SymmetricKey, SymmetricKey) {
        let salt = try transcriptSalt(sessionTranscriptBytes)
        let ikm = SymmetricKey(data: sharedSecret)
        let skDevice = HKDF<SHA256>.deriveKey(inputKeyMaterial: ikm, salt: salt, info: Data("SKDevice".utf8), outputByteCount: 32)
        let skReader = HKDF<SHA256>.deriveKey(inputKeyMaterial: ikm, salt: salt, info: Data("SKReader".utf8), outputByteCount: 32)
        return (skDevice, skReader)
    }

    /// ISO 18013-5 §9.1.3.5 `EMacKey` for verifying `deviceMac`: HKDF-SHA256 over the ECDH secret of the reader's
    /// `ephemeral` EReaderKey and the mdoc `deviceKey`, salted by the SessionTranscript.
    public static func deriveEMacKey(ephemeral: EphemeralKeyPair, deviceKey: EcPublicKey, sessionTranscriptBytes: [UInt8]) throws -> [UInt8] {
        try emacKey(sharedSecret: try ephemeral.sharedSecret(deviceKey), sessionTranscriptBytes: sessionTranscriptBytes)
    }

    /// The same `EMacKey` from an already-computed ECDH secret — the mdoc side, whose `DeviceKey` private half
    /// never leaves its secure area, so it derives `Zab` through the `SecureArea` port rather than from an
    /// `EphemeralKeyPair`. Both sides must reach identical bytes for `deviceMac` to verify.
    public static func emacKey(sharedSecret: [UInt8], sessionTranscriptBytes: [UInt8]) throws -> [UInt8] {
        let ikm = SymmetricKey(data: Data(sharedSecret))
        let key = HKDF<SHA256>.deriveKey(inputKeyMaterial: ikm, salt: try transcriptSalt(sessionTranscriptBytes),
                                         info: Data("EMacKey".utf8), outputByteCount: 32)
        return key.withUnsafeBytes { [UInt8]($0) }
    }

    // ISO 18013-5 §9.1.1.4: salt = SHA-256(SessionTranscriptBytes), SessionTranscriptBytes = #6.24(bstr .cbor SessionTranscript).
    private static func transcriptSalt(_ sessionTranscriptBytes: [UInt8]) throws -> Data {
        Data(SHA256.hash(data: Data(try CborEncoder.encode(.tagged(24, .bytes(sessionTranscriptBytes))))))
    }

    private func iv(_ identifier: [UInt8], _ counter: UInt32) -> Data {
        var iv = identifier + [0, 0, 0, 0]
        iv[8] = UInt8((counter >> 24) & 0xff); iv[9] = UInt8((counter >> 16) & 0xff)
        iv[10] = UInt8((counter >> 8) & 0xff); iv[11] = UInt8(counter & 0xff)
        return Data(iv)
    }
}
