package com.hopae.eudi.demo.adapters

import com.hopae.eudi.wallet.txlog.TransactionLogCodec
import com.hopae.eudi.wallet.txlog.TransactionLogEntry
import com.hopae.eudi.wallet.txlog.TransactionLogStore
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.io.File

/** [TransactionLogStore] that persists each entry as one JSON line (append-only) in [file]. */
class FileTransactionLogStore(private val file: File) : TransactionLogStore {
    private val mutex = Mutex()

    override suspend fun append(entry: TransactionLogEntry) = mutex.withLock {
        file.parentFile?.mkdirs()
        file.appendText(TransactionLogCodec.encode(entry) + "\n")
    }

    override suspend fun all(): List<TransactionLogEntry> = mutex.withLock {
        if (!file.exists()) return@withLock emptyList()
        file.readLines().filter { it.isNotBlank() }
            .mapNotNull { runCatching { TransactionLogCodec.decode(it) }.getOrNull() }
    }

    suspend fun clear() = mutex.withLock { runCatching { file.writeText("") }; Unit }
}
