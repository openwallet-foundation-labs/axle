import WalletAPI

/// In-memory StorageDriver for tests and Linux CI.
public actor InMemoryStorageDriver: StorageDriver {

    private var data: [String: [String: [UInt8]]] = [:]

    public init() {}

    public func put(collection: String, key: String, value: [UInt8]) async throws {
        data[collection, default: [:]][key] = value
    }

    public func get(collection: String, key: String) async throws -> [UInt8]? {
        data[collection]?[key]
    }

    public func delete(collection: String, key: String) async throws {
        data[collection]?.removeValue(forKey: key)
    }

    public func keys(collection: String) async throws -> [String] {
        data[collection].map { Array($0.keys) } ?? []
    }

    public func transaction(_ block: @Sendable (any StorageTx) async throws -> Void) async throws {
        try await block(Tx(driver: self))
    }

    private struct Tx: StorageTx {
        let driver: InMemoryStorageDriver

        func put(collection: String, key: String, value: [UInt8]) async throws {
            try await driver.put(collection: collection, key: key, value: value)
        }

        func get(collection: String, key: String) async throws -> [UInt8]? {
            try await driver.get(collection: collection, key: key)
        }

        func delete(collection: String, key: String) async throws {
            try await driver.delete(collection: collection, key: key)
        }
    }
}
