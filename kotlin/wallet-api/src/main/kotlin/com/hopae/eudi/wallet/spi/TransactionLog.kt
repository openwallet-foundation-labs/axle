package com.hopae.eudi.wallet.spi

import java.time.Instant

/**
 * Audit log of wallet transactions — presentations and issuances (ARF transaction logging / GDPR).
 * A cross-cutting port: injected by the host. Production wallets MUST persist these; the default is no-op.
 */
interface TransactionLog {
    suspend fun record(entry: TransactionLogEntry)
    suspend fun list(): List<TransactionLogEntry>
}

class TransactionLogEntry(
    val id: String,
    val type: TransactionType,
    val timestamp: Instant,
    /** Relying party / verifier client_id (presentation) or issuer (issuance). */
    val relyingParty: String?,
    val credentialIds: List<String>,
    /** Disclosed claim paths, dot-joined (presentation only). */
    val claimsDisclosed: List<String>,
    val status: TransactionStatus,
)

enum class TransactionType { Presentation, Issuance }

enum class TransactionStatus { Success, Declined, Failed }

/** Default no-op log. Replace with a persistent adapter for production audit. */
object NoOpTransactionLog : TransactionLog {
    override suspend fun record(entry: TransactionLogEntry) {}
    override suspend fun list(): List<TransactionLogEntry> = emptyList()
}
