package com.hopae.eudi.wallet.txlog

/** What kind of wallet activity a log entry records. */
enum class TransactionType { PRESENTATION, ISSUANCE }

/** Outcome of the activity. */
enum class TransactionStatus { SUCCESS, INCOMPLETE, ERROR }

/** The verifier a presentation went to (from the resolved request + trust decision). */
/** A localized string (BCP-47 `lang` + `value`), e.g. a WRPRC `purpose`. */
data class LocalizedText(val lang: String, val value: String)

/** How a presentation was delivered. */
enum class TransactionTransport { REMOTE, PROXIMITY, DC_API }

/**
 * The relying party a presentation was made to. Beyond identity + trust, the registration fields (from the
 * validated WRPRC / registrar dataset) are all optional — absent when the RP presented no registration, so
 * older records and unregistered RPs stay valid.
 */
class RelyingParty(
    val id: String,
    val name: String? = null,
    /** True when the verifier's request chained to a trust anchor. */
    val trusted: Boolean = false,
    /** Leaf-first DER of the verifier's certificate chain, if any. */
    val certificateChainDer: List<ByteArray> = emptyList(),
    /** client_id scheme (x509_san_dns, …), when known. */
    val clientIdScheme: String? = null,
    /** Registered semantic identifier of the RP (organizationIdentifier), from its registration. */
    val subject: String? = null,
    /** EU-level entitlements/roles the RP is registered for. */
    val entitlements: List<String> = emptyList(),
    /** The RP's declared purpose / intended use (why it asked), localized. */
    val purpose: List<LocalizedText> = emptyList(),
    /** When the RP operates through an intermediary. */
    val intermediaryName: String? = null,
    val intermediarySub: String? = null,
    /** True iff a registrar-issued WRPRC attested the registration (vs a self-declared dataset). */
    val attested: Boolean? = null,
    /** Token Status List result for the WRPRC: true = valid, false = revoked, null = not checked. */
    val statusValid: Boolean? = null,
    /** RPRC_21 attribute-scope result decided at consent time: true ⇒ the request asked for attributes outside
     *  the RP's registration; false ⇒ everything was in scope; null ⇒ no registration to check against. */
    val outOfScope: Boolean? = null,
)

/** One disclosed claim: its path and (optionally) the value that was shared. */
class LoggedClaim(val path: List<String>, val value: String? = null)

/** One credential involved in the activity, with the claims disclosed/received. */
class LoggedDocument(
    val format: String,
    /** vct (SD-JWT VC) or docType (mdoc). */
    val type: String? = null,
    val queryId: String? = null,
    val claims: List<LoggedClaim> = emptyList(),
)

/**
 * An audit-trail record of a presentation or issuance (transparency / GDPR). Optional raw request
 * and response bytes are kept for dispute resolution; the structured fields drive a history UI.
 */
class TransactionLogEntry(
    val id: String,
    /** epoch seconds. */
    val timestamp: Long,
    val type: TransactionType,
    val status: TransactionStatus,
    val relyingParty: RelyingParty? = null,
    val issuer: String? = null,
    val documents: List<LoggedDocument> = emptyList(),
    val error: String? = null,
    val rawRequest: ByteArray? = null,
    val rawResponse: ByteArray? = null,
    /** How a presentation was delivered (null for issuance / older records). */
    val transport: TransactionTransport? = null,
    /** Issuer display name (issuance), when known. */
    val issuerName: String? = null,
    /** Whether the issuer was established as a registered issuer — 2A (issuance), when checked. */
    val issuerRegistered: Boolean? = null,
)

/** Append-only persistence for transaction log entries (host-provided; see [InMemoryTransactionLogStore]). */
interface TransactionLogStore {
    suspend fun append(entry: TransactionLogEntry)
    suspend fun all(): List<TransactionLogEntry>
}

/** A non-persistent reference store — fine for tests and ephemeral sessions. */
class InMemoryTransactionLogStore : TransactionLogStore {
    private val entries = ArrayList<TransactionLogEntry>()
    private val lock = Any()
    override suspend fun append(entry: TransactionLogEntry) { synchronized(lock) { entries.add(entry) } }
    override suspend fun all(): List<TransactionLogEntry> = synchronized(lock) { entries.toList() }
}

/**
 * Records wallet activity and answers history queries over a [TransactionLogStore]. Ids and time
 * come from injected generators (no ambient Random/Clock in the SDK), keeping it deterministic in
 * tests and host-controlled in production.
 */
class TransactionLog(
    private val store: TransactionLogStore,
    private val idGenerator: () -> String,
    private val clock: () -> Long = { System.currentTimeMillis() / 1000 },
) {
    suspend fun recordPresentation(
        relyingParty: RelyingParty,
        documents: List<LoggedDocument>,
        status: TransactionStatus = TransactionStatus.SUCCESS,
        error: String? = null,
        rawRequest: ByteArray? = null,
        rawResponse: ByteArray? = null,
        transport: TransactionTransport? = null,
    ): TransactionLogEntry = record(
        TransactionLogEntry(
            idGenerator(), clock(), TransactionType.PRESENTATION, status, relyingParty, null, documents, error,
            rawRequest, rawResponse, transport,
        )
    )

    suspend fun recordIssuance(
        issuer: String,
        documents: List<LoggedDocument>,
        status: TransactionStatus = TransactionStatus.SUCCESS,
        error: String? = null,
        issuerName: String? = null,
        issuerRegistered: Boolean? = null,
    ): TransactionLogEntry = record(
        TransactionLogEntry(
            idGenerator(), clock(), TransactionType.ISSUANCE, status, null, issuer, documents, error,
            issuerName = issuerName, issuerRegistered = issuerRegistered,
        )
    )

    private suspend fun record(entry: TransactionLogEntry): TransactionLogEntry {
        store.append(entry)
        return entry
    }

    /** All entries, most recent first. */
    suspend fun history(): List<TransactionLogEntry> = store.all().sortedByDescending { it.timestamp }

    /** Filtered history — any combination of type, relying-party id, and a time window (epoch seconds). */
    suspend fun query(
        type: TransactionType? = null,
        relyingPartyId: String? = null,
        since: Long? = null,
        until: Long? = null,
    ): List<TransactionLogEntry> = history().filter { e ->
        (type == null || e.type == type) &&
            (relyingPartyId == null || e.relyingParty?.id == relyingPartyId) &&
            (since == null || e.timestamp >= since) &&
            (until == null || e.timestamp <= until)
    }
}
