package com.hopae.eudi.demo.adapters

import android.util.Base64
import com.hopae.eudi.wallet.spi.StorageDriver
import com.hopae.eudi.wallet.spi.StorageTx
import java.io.File

/**
 * Persistent [StorageDriver] over the app's private files directory. Debug-grade: values are stored as
 * plain files. A production wallet should wrap this with an encrypted store (e.g. EncryptedFile / SQLCipher).
 */
class FileStorageDriver(private val baseDir: File) : StorageDriver {

    private fun collectionDir(collection: String) = File(baseDir, enc(collection)).apply { mkdirs() }
    private fun file(collection: String, key: String) = File(collectionDir(collection), enc(key))

    override suspend fun put(collection: String, key: String, value: ByteArray) {
        file(collection, key).writeBytes(value)
    }

    override suspend fun get(collection: String, key: String): ByteArray? =
        file(collection, key).takeIf { it.exists() }?.readBytes()

    override suspend fun delete(collection: String, key: String) {
        file(collection, key).delete()
    }

    override suspend fun keys(collection: String): List<String> =
        collectionDir(collection).listFiles()?.map { dec(it.name) } ?: emptyList()

    override suspend fun transaction(block: suspend StorageTx.() -> Unit) {
        // Debug-grade: no rollback. Production should batch writes atomically.
        object : StorageTx {
            override suspend fun put(collection: String, key: String, value: ByteArray) = this@FileStorageDriver.put(collection, key, value)
            override suspend fun get(collection: String, key: String) = this@FileStorageDriver.get(collection, key)
            override suspend fun delete(collection: String, key: String) = this@FileStorageDriver.delete(collection, key)
        }.block()
    }

    private fun enc(s: String) = Base64.encodeToString(s.toByteArray(), Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)
    private fun dec(s: String) = String(Base64.decode(s, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING))
}
