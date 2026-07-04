package com.hopae.eudi.wallet.txlog

import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

class TransactionLogTest {

    private fun log(store: TransactionLogStore, start: Long = 1_000): TransactionLog {
        var id = 0
        var now = start
        return TransactionLog(store, idGenerator = { "tx-${id++}" }, clock = { now++ })
    }

    private val pidDoc = LoggedDocument(
        format = "dc+sd-jwt", type = "urn:eudi:pid:1", queryId = "query_0",
        claims = listOf(LoggedClaim(listOf("family_name"), "Han"), LoggedClaim(listOf("given_name"), "Jongho")),
    )

    @Test
    fun recordsAndReturnsHistoryNewestFirst() = runBlocking {
        val log = log(InMemoryTransactionLogStore())
        log.recordIssuance("https://issuer.eudiw.dev", listOf(pidDoc))
        log.recordPresentation(RelyingParty("verifier.eudiw.dev", "EUDI Remote Verifier", trusted = true), listOf(pidDoc))

        val history = log.history()
        assertEquals(2, history.size)
        assertEquals(TransactionType.PRESENTATION, history[0].type) // newest first
        assertEquals(TransactionType.ISSUANCE, history[1].type)
        assertEquals("EUDI Remote Verifier", history[0].relyingParty?.name)
        assertTrue(history[0].relyingParty?.trusted == true)
    }

    @Test
    fun queriesByTypeAndRelyingPartyAndWindow() = runBlocking {
        val log = log(InMemoryTransactionLogStore(), start = 100)
        log.recordPresentation(RelyingParty("rp-a"), listOf(pidDoc)) // ts 100
        log.recordPresentation(RelyingParty("rp-b"), listOf(pidDoc)) // ts 101
        log.recordIssuance("iss", listOf(pidDoc))                    // ts 102

        assertEquals(2, log.query(type = TransactionType.PRESENTATION).size)
        assertEquals(1, log.query(relyingPartyId = "rp-b").size)
        assertEquals("rp-b", log.query(relyingPartyId = "rp-b").single().relyingParty?.id)
        assertEquals(2, log.query(since = 101).size)              // ts 101, 102
        assertEquals(1, log.query(type = TransactionType.PRESENTATION, until = 100).size)
    }

    @Test
    fun jsonRoundTripPreservesFields() = runBlocking {
        val entry = TransactionLogEntry(
            id = "tx-1", timestamp = 1_700_000_000, type = TransactionType.PRESENTATION, status = TransactionStatus.SUCCESS,
            relyingParty = RelyingParty("verifier.eudiw.dev", "EUDI Remote Verifier", true, listOf(byteArrayOf(0x30, 0x01, 0x02))),
            documents = listOf(pidDoc),
            rawRequest = byteArrayOf(1, 2, 3), rawResponse = byteArrayOf(4, 5),
        )
        val decoded = TransactionLogCodec.decode(TransactionLogCodec.encode(entry))

        assertEquals(entry.id, decoded.id)
        assertEquals(entry.timestamp, decoded.timestamp)
        assertEquals(entry.type, decoded.type)
        assertEquals(entry.status, decoded.status)
        assertEquals("EUDI Remote Verifier", decoded.relyingParty?.name)
        assertTrue(decoded.relyingParty?.trusted == true)
        assertContentEquals(byteArrayOf(0x30, 0x01, 0x02), decoded.relyingParty?.certificateChainDer?.first())
        assertEquals("urn:eudi:pid:1", decoded.documents.single().type)
        assertEquals(listOf("family_name"), decoded.documents.single().claims.first().path)
        assertEquals("Han", decoded.documents.single().claims.first().value)
        assertContentEquals(byteArrayOf(1, 2, 3), decoded.rawRequest)
        assertContentEquals(byteArrayOf(4, 5), decoded.rawResponse)
    }

    @Test
    fun issuanceEntryOmitsRelyingParty() = runBlocking {
        val decoded = TransactionLogCodec.decode(
            TransactionLogCodec.encode(TransactionLog(InMemoryTransactionLogStore(), { "tx-0" }, { 5 }).recordIssuance("iss", listOf(pidDoc)))
        )
        assertEquals(TransactionType.ISSUANCE, decoded.type)
        assertEquals("iss", decoded.issuer)
        assertNull(decoded.relyingParty)
    }
}
