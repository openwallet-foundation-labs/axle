import Crypto
import Foundation

/// ECDSA verification via swift-crypto (CryptoKit-compatible; BoringSSL on Linux).
/// Core rule: only public-key operations live in core — private-key signing goes
/// through the SecureArea port (see WalletAPI).
enum Ecdsa {

    static func verify(key: EcPublicKey, algorithm: CoseAlgorithm, data: [UInt8], rawSignature: [UInt8]) -> Bool {
        guard rawSignature.count == 2 * key.curve.coordinateSize else { return false }
        var x963: [UInt8] = [0x04]
        x963 += leftPad(key.x, key.curve.coordinateSize)
        x963 += leftPad(key.y, key.curve.coordinateSize)
        do {
            switch (key.curve, algorithm) {
            case (.p256, .es256):
                let pk = try P256.Signing.PublicKey(x963Representation: x963)
                let sig = try P256.Signing.ECDSASignature(rawRepresentation: rawSignature)
                return pk.isValidSignature(sig, for: Data(data))
            case (.p384, .es384):
                let pk = try P384.Signing.PublicKey(x963Representation: x963)
                let sig = try P384.Signing.ECDSASignature(rawRepresentation: rawSignature)
                return pk.isValidSignature(sig, for: Data(data))
            case (.p521, .es512):
                let pk = try P521.Signing.PublicKey(x963Representation: x963)
                let sig = try P521.Signing.ECDSASignature(rawRepresentation: rawSignature)
                return pk.isValidSignature(sig, for: Data(data))
            default:
                return false // curve/alg mismatch — mdoc profiles always pair them
            }
        } catch {
            return false
        }
    }

    private static func leftPad(_ bytes: [UInt8], _ size: Int) -> [UInt8] {
        bytes.count >= size ? bytes : [UInt8](repeating: 0, count: size - bytes.count) + bytes
    }
}
