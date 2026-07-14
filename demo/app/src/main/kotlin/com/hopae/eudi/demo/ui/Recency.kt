package com.hopae.eudi.demo.ui

import com.hopae.eudi.wallet.Credential
import com.hopae.eudi.wallet.txlog.TransactionLogEntry

/**
 * Orders credentials most-recently-used first: the later of the credential's issuance time and the newest
 * transaction-log entry that presented a document of the same type. Ties fall back to issuance order.
 */
fun List<Credential>.byRecentUse(txs: List<TransactionLogEntry>): List<Credential> {
    fun lastUsed(cred: Credential): Long {
        val type = credType(cred)
        val txMillis = txs.filter { e -> e.documents.any { it.type == type } }.maxOfOrNull { it.timestamp * 1000 } ?: 0L
        return maxOf(cred.createdAt.toEpochMilli(), txMillis)
    }
    return sortedByDescending { lastUsed(it) }
}
