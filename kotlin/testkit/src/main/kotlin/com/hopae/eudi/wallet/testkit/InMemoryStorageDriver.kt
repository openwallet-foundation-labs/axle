package com.hopae.eudi.wallet.testkit

import com.hopae.eudi.wallet.spi.StorageDriver
import com.hopae.eudi.wallet.spi.StorageTx
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

/** In-memory StorageDriver for tests and Linux CI. Values are defensively copied. */
class InMemoryStorageDriver : StorageDriver {

    private val mutex = Mutex()
    private val data = mutableMapOf<String, MutableMap<String, ByteArray>>()

    override suspend fun put(collection: String, key: String, value: ByteArray) {
        mutex.withLock { putLocked(collection, key, value) }
    }

    override suspend fun get(collection: String, key: String): ByteArray? =
        mutex.withLock { getLocked(collection, key) }

    override suspend fun delete(collection: String, key: String) {
        mutex.withLock { data[collection]?.remove(key) }
    }

    override suspend fun keys(collection: String): List<String> =
        mutex.withLock { data[collection]?.keys?.toList() ?: emptyList() }

    override suspend fun transaction(block: suspend StorageTx.() -> Unit) {
        mutex.withLock { Tx().block() }
    }

    private fun putLocked(collection: String, key: String, value: ByteArray) {
        data.getOrPut(collection) { mutableMapOf() }[key] = value.copyOf()
    }

    private fun getLocked(collection: String, key: String): ByteArray? =
        data[collection]?.get(key)?.copyOf()

    private inner class Tx : StorageTx {
        override suspend fun put(collection: String, key: String, value: ByteArray) =
            putLocked(collection, key, value)

        override suspend fun get(collection: String, key: String): ByteArray? =
            getLocked(collection, key)

        override suspend fun delete(collection: String, key: String) {
            data[collection]?.remove(key)
        }
    }
}
