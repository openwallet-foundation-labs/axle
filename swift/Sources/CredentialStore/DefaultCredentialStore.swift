import Foundation
import WalletAPI

public enum CredentialStoreChange: Equatable, Sendable {
    case added(CredentialId)
    case updated(CredentialId)
    case removed(CredentialId)
}

/// The instance picked for a presentation, plus how many remain afterwards.
public struct ConsumedInstance: Sendable {
    public let instance: CredentialInstance
    public let remaining: Int
}

/// Envelope-level credential store over a `StorageDriver` port (M1).
/// The public Credential facade (claims views, status) is assembled on top in M2+.
public actor DefaultCredentialStore {

    private static let collection = "credentials"

    private let driver: any StorageDriver
    private var continuations: [UUID: AsyncStream<CredentialStoreChange>.Continuation] = [:]

    public init(driver: any StorageDriver) {
        self.driver = driver
    }

    /// Reactive source for list screens. Each call returns an independent stream.
    public func changes() -> AsyncStream<CredentialStoreChange> {
        var captured: AsyncStream<CredentialStoreChange>.Continuation!
        let stream = AsyncStream<CredentialStoreChange> { captured = $0 }
        let id = UUID()
        continuations[id] = captured
        captured.onTermination = { [weak self] _ in
            Task { await self?.removeContinuation(id) }
        }
        return stream
    }

    public func save(_ envelope: CredentialEnvelope) async throws {
        let existed = try await driver.get(collection: Self.collection, key: envelope.id.value) != nil
        try await driver.put(
            collection: Self.collection,
            key: envelope.id.value,
            value: try EnvelopeCodec.encode(envelope)
        )
        broadcast(existed ? .updated(envelope.id) : .added(envelope.id))
    }

    public func get(_ id: CredentialId) async throws -> CredentialEnvelope? {
        try await driver.get(collection: Self.collection, key: id.value).map { try EnvelopeCodec.decode($0) }
    }

    public func list() async throws -> [CredentialEnvelope] {
        var out: [CredentialEnvelope] = []
        for key in try await driver.keys(collection: Self.collection) {
            if let envelope = try await get(CredentialId(key)) {
                out.append(envelope)
            }
        }
        return out
    }

    public func delete(_ id: CredentialId) async throws {
        guard try await driver.get(collection: Self.collection, key: id.value) != nil else { return }
        try await driver.delete(collection: Self.collection, key: id.value)
        broadcast(.removed(id))
    }

    /// Picks a credential instance for presentation per the stored `KeyUse` policy:
    /// rotate — least-used instance, use counter incremented;
    /// oneTime — instance removed from the envelope (single-use keys, HAIP unlinkability).
    /// Returns nil when the envelope is missing, not issued, or exhausted.
    public func consumeInstance(_ id: CredentialId) async throws -> ConsumedInstance? {
        guard
            let envelope = try await get(id),
            case let .issued(policy, instances) = envelope.lifecycle,
            !instances.isEmpty
        else { return nil }

        let pickedIndex = instances.indices.min { instances[$0].useCount < instances[$1].useCount }!
        let picked = instances[pickedIndex]

        var updated = instances
        switch policy.use {
        case .rotate:
            updated[pickedIndex] = CredentialInstance(key: picked.key, payload: picked.payload, useCount: picked.useCount + 1)
        case .oneTime:
            updated.remove(at: pickedIndex)
        }

        let newEnvelope = CredentialEnvelope(
            id: envelope.id,
            format: envelope.format,
            createdAt: envelope.createdAt,
            lifecycle: .issued(policy: policy, instances: updated),
            metadata: envelope.metadata // preserve issuer/display + trust flags across a presentation
        )
        try await driver.put(
            collection: Self.collection,
            key: id.value,
            value: try EnvelopeCodec.encode(newEnvelope)
        )
        broadcast(.updated(id))
        return ConsumedInstance(instance: picked, remaining: updated.count)
    }

    private func removeContinuation(_ id: UUID) {
        continuations.removeValue(forKey: id)
    }

    private func broadcast(_ change: CredentialStoreChange) {
        for continuation in continuations.values {
            continuation.yield(change)
        }
    }
}
