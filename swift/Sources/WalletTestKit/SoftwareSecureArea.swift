import CborCose
import Crypto
import Foundation
import WalletAPI

public enum SoftwareSecureAreaError: Error {
    case hardwareRequired
    case algorithmMismatch
    case curveMismatch
    case unknownKey
}

/// In-memory software SecureArea for tests, Linux CI, and desktop/server hosts.
/// No hardware backing, no user auth, no attestation — capabilities say so honestly.
public actor SoftwareSecureArea: SecureArea {

    private struct Entry {
        let raw: Data
        let algorithm: SigningAlgorithm
        let publicKey: EcPublicKey
    }

    public nonisolated let id: SecureAreaId
    public nonisolated let capabilities = SecureAreaCapabilities(
        algorithms: [.es256, .es384, .es512],
        hardwareBacked: false,
        userAuthentication: false,
        keyAttestation: false,
        keyAgreement: true
    )

    private var keys: [String: Entry] = [:]
    private var counter = 0

    public init(id: SecureAreaId = SecureAreaId("software")) {
        self.id = id
    }

    public func createKey(spec: KeySpec) async throws -> KeyInfo {
        guard spec.hardware != .required else { throw SoftwareSecureAreaError.hardwareRequired }
        counter += 1
        let alias = "key-\(counter)"
        let raw: Data
        let x963: Data
        switch spec.algorithm {
        case .es256:
            let k = P256.Signing.PrivateKey()
            raw = k.rawRepresentation
            x963 = k.publicKey.x963Representation
        case .es384:
            let k = P384.Signing.PrivateKey()
            raw = k.rawRepresentation
            x963 = k.publicKey.x963Representation
        case .es512:
            let k = P521.Signing.PrivateKey()
            raw = k.rawRepresentation
            x963 = k.publicKey.x963Representation
        }
        let publicKey = Self.splitX963(spec.algorithm.curve, x963)
        keys[alias] = Entry(raw: raw, algorithm: spec.algorithm, publicKey: publicKey)
        return KeyInfo(
            handle: KeyHandle(secureArea: id, alias: alias),
            algorithm: spec.algorithm,
            publicKey: publicKey
        )
    }

    public func publicKey(key: KeyHandle) async throws -> EcPublicKey {
        try entry(key).publicKey
    }

    public func sign(key: KeyHandle, algorithm: SigningAlgorithm, data: [UInt8], hint: AuthorizationHint?) async throws -> [UInt8] {
        let e = try entry(key)
        guard algorithm == e.algorithm else { throw SoftwareSecureAreaError.algorithmMismatch }
        switch algorithm {
        case .es256:
            return [UInt8](try P256.Signing.PrivateKey(rawRepresentation: e.raw).signature(for: Data(data)).rawRepresentation)
        case .es384:
            return [UInt8](try P384.Signing.PrivateKey(rawRepresentation: e.raw).signature(for: Data(data)).rawRepresentation)
        case .es512:
            return [UInt8](try P521.Signing.PrivateKey(rawRepresentation: e.raw).signature(for: Data(data)).rawRepresentation)
        }
    }

    public func keyAgreement(key: KeyHandle, peerPublicKey: EcPublicKey, hint: AuthorizationHint?) async throws -> [UInt8] {
        let e = try entry(key)
        guard peerPublicKey.curve == e.algorithm.curve else { throw SoftwareSecureAreaError.curveMismatch }
        let size = e.algorithm.curve.coordinateSize
        let x963 = Data([0x04] + leftPad(peerPublicKey.x, size) + leftPad(peerPublicKey.y, size))
        switch e.algorithm {
        case .es256:
            let secret = try P256.KeyAgreement.PrivateKey(rawRepresentation: e.raw)
                .sharedSecretFromKeyAgreement(with: P256.KeyAgreement.PublicKey(x963Representation: x963))
            return secret.withUnsafeBytes { [UInt8]($0) }
        case .es384:
            let secret = try P384.KeyAgreement.PrivateKey(rawRepresentation: e.raw)
                .sharedSecretFromKeyAgreement(with: P384.KeyAgreement.PublicKey(x963Representation: x963))
            return secret.withUnsafeBytes { [UInt8]($0) }
        case .es512:
            let secret = try P521.KeyAgreement.PrivateKey(rawRepresentation: e.raw)
                .sharedSecretFromKeyAgreement(with: P521.KeyAgreement.PublicKey(x963Representation: x963))
            return secret.withUnsafeBytes { [UInt8]($0) }
        }
    }

    public func attestation(key: KeyHandle, challenge: [UInt8]) async throws -> KeyAttestation? {
        _ = try entry(key)
        return nil
    }

    public func deleteKey(key: KeyHandle) async throws {
        keys.removeValue(forKey: key.alias)
    }

    private func entry(_ key: KeyHandle) throws -> Entry {
        guard key.secureArea == id, let e = keys[key.alias] else {
            throw SoftwareSecureAreaError.unknownKey
        }
        return e
    }

    private static func splitX963(_ curve: EcCurve, _ x963: Data) -> EcPublicKey {
        let bytes = [UInt8](x963)
        let size = curve.coordinateSize
        return EcPublicKey(
            curve: curve,
            x: Array(bytes[1...size]),
            y: Array(bytes[(1 + size)...])
        )
    }

    private func leftPad(_ bytes: [UInt8], _ size: Int) -> [UInt8] {
        bytes.count >= size ? bytes : [UInt8](repeating: 0, count: size - bytes.count) + bytes
    }
}
