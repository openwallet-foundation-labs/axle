import Foundation

/// What kind of wallet activity a log entry records.
public enum TransactionType: String, Sendable { case presentation = "PRESENTATION", issuance = "ISSUANCE" }

/// Outcome of the activity.
public enum TransactionStatus: String, Sendable { case success = "SUCCESS", incomplete = "INCOMPLETE", error = "ERROR" }

/// The verifier a presentation went to (from the resolved request + trust decision).
public struct RelyingParty: Sendable {
    public let id: String
    public let name: String?
    /// True when the verifier's request chained to a trust anchor.
    public let trusted: Bool
    /// Leaf-first DER of the verifier's certificate chain, if any.
    public let certificateChainDer: [[UInt8]]

    public init(id: String, name: String? = nil, trusted: Bool = false, certificateChainDer: [[UInt8]] = []) {
        self.id = id; self.name = name; self.trusted = trusted; self.certificateChainDer = certificateChainDer
    }
}

/// One disclosed claim: its path and (optionally) the value that was shared.
public struct LoggedClaim: Sendable {
    public let path: [String]
    public let value: String?
    public init(path: [String], value: String? = nil) { self.path = path; self.value = value }
}

/// One credential involved in the activity, with the claims disclosed/received.
public struct LoggedDocument: Sendable {
    public let format: String
    /// vct (SD-JWT VC) or docType (mdoc).
    public let type: String?
    public let queryId: String?
    public let claims: [LoggedClaim]
    public init(format: String, type: String? = nil, queryId: String? = nil, claims: [LoggedClaim] = []) {
        self.format = format; self.type = type; self.queryId = queryId; self.claims = claims
    }
}

/// An audit-trail record of a presentation or issuance (transparency / GDPR). Optional raw request
/// and response bytes are kept for dispute resolution; the structured fields drive a history UI.
public struct TransactionLogEntry: Sendable {
    public let id: String
    /// epoch seconds.
    public let timestamp: Int64
    public let type: TransactionType
    public let status: TransactionStatus
    public let relyingParty: RelyingParty?
    public let issuer: String?
    public let documents: [LoggedDocument]
    public let error: String?
    public let rawRequest: [UInt8]?
    public let rawResponse: [UInt8]?

    public init(id: String, timestamp: Int64, type: TransactionType, status: TransactionStatus,
                relyingParty: RelyingParty? = nil, issuer: String? = nil, documents: [LoggedDocument] = [],
                error: String? = nil, rawRequest: [UInt8]? = nil, rawResponse: [UInt8]? = nil) {
        self.id = id; self.timestamp = timestamp; self.type = type; self.status = status
        self.relyingParty = relyingParty; self.issuer = issuer; self.documents = documents
        self.error = error; self.rawRequest = rawRequest; self.rawResponse = rawResponse
    }
}

/// Append-only persistence for transaction log entries (host-provided; see `InMemoryTransactionLogStore`).
public protocol TransactionLogStore: Sendable {
    func append(_ entry: TransactionLogEntry) async
    func all() async -> [TransactionLogEntry]
}

/// A non-persistent reference store — fine for tests and ephemeral sessions.
public actor InMemoryTransactionLogStore: TransactionLogStore {
    private var entries: [TransactionLogEntry] = []
    public init() {}
    public func append(_ entry: TransactionLogEntry) { entries.append(entry) }
    public func all() -> [TransactionLogEntry] { entries }
}

/// Records wallet activity and answers history queries over a `TransactionLogStore`. Ids and time
/// come from injected generators (no ambient Random/Clock in the SDK).
public struct TransactionLog {
    private let store: any TransactionLogStore
    private let idGenerator: () -> String
    private let clock: () -> Int64

    public init(store: any TransactionLogStore, idGenerator: @escaping () -> String,
                clock: @escaping () -> Int64 = { Int64(Date().timeIntervalSince1970) }) {
        self.store = store; self.idGenerator = idGenerator; self.clock = clock
    }

    @discardableResult
    public func recordPresentation(relyingParty: RelyingParty, documents: [LoggedDocument],
                                   status: TransactionStatus = .success, error: String? = nil,
                                   rawRequest: [UInt8]? = nil, rawResponse: [UInt8]? = nil) async -> TransactionLogEntry {
        await record(TransactionLogEntry(id: idGenerator(), timestamp: clock(), type: .presentation, status: status,
                                         relyingParty: relyingParty, documents: documents, error: error,
                                         rawRequest: rawRequest, rawResponse: rawResponse))
    }

    @discardableResult
    public func recordIssuance(issuer: String, documents: [LoggedDocument],
                               status: TransactionStatus = .success, error: String? = nil) async -> TransactionLogEntry {
        await record(TransactionLogEntry(id: idGenerator(), timestamp: clock(), type: .issuance, status: status,
                                         issuer: issuer, documents: documents, error: error))
    }

    private func record(_ entry: TransactionLogEntry) async -> TransactionLogEntry {
        await store.append(entry)
        return entry
    }

    /// All entries, most recent first.
    public func history() async -> [TransactionLogEntry] {
        await store.all().sorted { $0.timestamp > $1.timestamp }
    }

    /// Filtered history — any combination of type, relying-party id, and a time window (epoch seconds).
    public func query(type: TransactionType? = nil, relyingPartyId: String? = nil,
                      since: Int64? = nil, until: Int64? = nil) async -> [TransactionLogEntry] {
        await history().filter { e in
            (type == nil || e.type == type)
                && (relyingPartyId == nil || e.relyingParty?.id == relyingPartyId)
                && (since == nil || e.timestamp >= since!)
                && (until == nil || e.timestamp <= until!)
        }
    }
}
