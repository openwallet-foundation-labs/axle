import Foundation

/// Audit log of wallet transactions — presentations and issuances (ARF transaction logging / GDPR).
/// A cross-cutting port: injected by the host. Production wallets MUST persist these; the default is no-op.
public protocol TransactionLog: Sendable {
    func record(_ entry: TransactionLogEntry) async throws
    func list() async throws -> [TransactionLogEntry]
}

public struct TransactionLogEntry: Sendable {
    public let id: String
    public let type: TransactionType
    public let timestamp: Date
    /// Relying party / verifier client_id (presentation) or issuer (issuance).
    public let relyingParty: String?
    public let credentialIds: [String]
    /// Disclosed claim paths, dot-joined (presentation only).
    public let claimsDisclosed: [String]
    public let status: TransactionStatus

    public init(id: String, type: TransactionType, timestamp: Date, relyingParty: String?,
                credentialIds: [String], claimsDisclosed: [String], status: TransactionStatus) {
        self.id = id
        self.type = type
        self.timestamp = timestamp
        self.relyingParty = relyingParty
        self.credentialIds = credentialIds
        self.claimsDisclosed = claimsDisclosed
        self.status = status
    }
}

public enum TransactionType: Sendable { case presentation, issuance }

public enum TransactionStatus: Sendable { case success, declined, failed }

/// Default no-op log. Replace with a persistent adapter for production audit.
public struct NoOpTransactionLog: TransactionLog {
    public init() {}
    public func record(_ entry: TransactionLogEntry) async throws {}
    public func list() async throws -> [TransactionLogEntry] { [] }
}
