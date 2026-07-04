import CborCose
import WalletAPI

/*
 * Port contract test suites (framework-agnostic).
 *
 * "어댑터 자격 = 계약 테스트 통과": the same checks run against SoftwareSecureArea /
 * InMemoryStorageDriver on Linux CI and against real adapters in the device lab.
 */

public struct ContractViolation: Error, CustomStringConvertible {
    public let description: String

    init(_ description: String) {
        self.description = description
    }
}

private func require(_ condition: Bool, _ message: @autoclosure () -> String) throws {
    if !condition { throw ContractViolation(message()) }
}

public enum SecureAreaContract {

    public static func verify(_ area: any SecureArea) async throws {
        try require(!area.capabilities.algorithms.isEmpty, "capabilities must declare at least one algorithm")

        for algorithm in area.capabilities.algorithms {
            let info = try await area.createKey(spec: KeySpec(secureArea: area.id, algorithm: algorithm))
            try require(info.handle.secureArea == area.id, "\(algorithm): handle must reference this area")
            try require(info.algorithm == algorithm, "\(algorithm): KeyInfo.algorithm mismatch")

            let fetched = try await area.publicKey(key: info.handle)
            try require(
                fetched.x == info.publicKey.x && fetched.y == info.publicKey.y,
                "\(algorithm): publicKey(handle) must equal createKey's public key"
            )

            let data = [UInt8]("port-contract-test".utf8)
            let signature = try await area.sign(key: info.handle, algorithm: algorithm, data: data, hint: nil)
            try require(
                signature.count == 2 * algorithm.curve.coordinateSize,
                "\(algorithm): signature must be raw r||s, got \(signature.count) bytes"
            )
            try require(
                Ecdsa.verify(key: info.publicKey, algorithm: algorithm.coseAlgorithm, data: data, rawSignature: signature),
                "\(algorithm): signature must verify against the key's public key"
            )
            try require(
                !Ecdsa.verify(key: info.publicKey, algorithm: algorithm.coseAlgorithm, data: [UInt8]("other-data".utf8), rawSignature: signature),
                "\(algorithm): signature must not verify for different data"
            )

            if area.capabilities.keyAttestation {
                let challenge = (0..<32).map { UInt8($0) }
                let attestation = try await area.attestation(key: info.handle, challenge: challenge)
                try require(attestation != nil, "\(algorithm): area declares keyAttestation but returned nil")
            }

            try await area.deleteKey(key: info.handle)
            var signAfterDeleteFailed = false
            do {
                _ = try await area.sign(key: info.handle, algorithm: algorithm, data: data, hint: nil)
            } catch {
                signAfterDeleteFailed = true
            }
            try require(signAfterDeleteFailed, "\(algorithm): signing with a deleted key must fail")
        }

        if area.capabilities.keyAgreement {
            let algorithm = area.capabilities.algorithms.first!
            let a = try await area.createKey(spec: KeySpec(secureArea: area.id, algorithm: algorithm))
            let b = try await area.createKey(spec: KeySpec(secureArea: area.id, algorithm: algorithm))
            let s1 = try await area.keyAgreement(key: a.handle, peerPublicKey: b.publicKey, hint: nil)
            let s2 = try await area.keyAgreement(key: b.handle, peerPublicKey: a.publicKey, hint: nil)
            try require(!s1.isEmpty && s1 == s2, "ECDH must be symmetric and non-empty")
            try await area.deleteKey(key: a.handle)
            try await area.deleteKey(key: b.handle)
        }
    }
}

public enum StorageDriverContract {

    public static func verify(_ driver: any StorageDriver) async throws {
        let c = "contract-test"

        try require(try await driver.get(collection: c, key: "missing") == nil, "missing key must read as nil")

        try await driver.put(collection: c, key: "k1", value: [1, 2, 3])
        try require(try await driver.get(collection: c, key: "k1") == [1, 2, 3], "put/get roundtrip")

        try await driver.put(collection: c, key: "k1", value: [9])
        try require(try await driver.get(collection: c, key: "k1") == [9], "overwrite must replace value")

        try await driver.put(collection: c, key: "k2", value: [2])
        try require(Set(try await driver.keys(collection: c)) == ["k1", "k2"], "keys() must list stored keys")

        try await driver.delete(collection: c, key: "k1")
        try require(try await driver.get(collection: c, key: "k1") == nil, "delete must remove the value")

        try await driver.transaction { tx in
            try await tx.put(collection: c, key: "k3", value: [3])
            guard try await tx.get(collection: c, key: "k2") == [2] else {
                throw ContractViolation("tx must see pre-existing state")
            }
            guard try await tx.get(collection: c, key: "k3") == [3] else {
                throw ContractViolation("tx must see its own writes")
            }
            try await tx.delete(collection: c, key: "k2")
        }
        try require(try await driver.get(collection: c, key: "k3") == [3], "tx writes must persist")
        try require(try await driver.get(collection: c, key: "k2") == nil, "tx deletes must persist")

        try await driver.delete(collection: c, key: "k3")
    }
}
