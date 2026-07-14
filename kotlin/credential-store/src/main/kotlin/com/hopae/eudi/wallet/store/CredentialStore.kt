package com.hopae.eudi.wallet.store

import com.hopae.eudi.wallet.spi.CredentialId
import com.hopae.eudi.wallet.spi.KeyUse
import com.hopae.eudi.wallet.spi.StorageDriver
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

sealed interface CredentialStoreChange {
    val id: CredentialId

    data class Added(override val id: CredentialId) : CredentialStoreChange
    data class Updated(override val id: CredentialId) : CredentialStoreChange
    data class Removed(override val id: CredentialId) : CredentialStoreChange
}

/** The instance picked for a presentation, plus how many remain afterwards. */
class ConsumedInstance(val instance: CredentialInstance, val remaining: Int)

/**
 * Envelope-level credential store over a [StorageDriver] port (M1).
 * The public Credential facade (claims views, status) is assembled on top in M2+.
 */
class CredentialStore(private val driver: StorageDriver) {

    private companion object {
        const val COLLECTION = "credentials"
    }

    private val mutex = Mutex()
    private val _changes = MutableSharedFlow<CredentialStoreChange>(extraBufferCapacity = 64)

    /** Reactive source for list screens; emissions never suspend the writer. */
    val changes: SharedFlow<CredentialStoreChange> get() = _changes

    suspend fun save(envelope: CredentialEnvelope) {
        mutex.withLock {
            val existed = driver.get(COLLECTION, envelope.id.value) != null
            driver.put(COLLECTION, envelope.id.value, EnvelopeCodec.encode(envelope))
            _changes.tryEmit(
                if (existed) CredentialStoreChange.Updated(envelope.id)
                else CredentialStoreChange.Added(envelope.id)
            )
        }
    }

    suspend fun get(id: CredentialId): CredentialEnvelope? =
        driver.get(COLLECTION, id.value)?.let(EnvelopeCodec::decode)

    suspend fun list(): List<CredentialEnvelope> =
        driver.keys(COLLECTION).mapNotNull { get(CredentialId(it)) }

    suspend fun delete(id: CredentialId) {
        mutex.withLock {
            if (driver.get(COLLECTION, id.value) != null) {
                driver.delete(COLLECTION, id.value)
                _changes.tryEmit(CredentialStoreChange.Removed(id))
            }
        }
    }

    /**
     * Picks a credential instance for presentation per the stored [KeyUse] policy:
     * Rotate — least-used instance, use counter incremented;
     * OneTime — instance removed from the envelope (single-use keys, HAIP unlinkability).
     * Returns null when the envelope is missing, not issued, or exhausted.
     */
    suspend fun consumeInstance(id: CredentialId): ConsumedInstance? = mutex.withLock {
        val envelope = get(id) ?: return null
        val issued = envelope.lifecycle as? EnvelopeLifecycle.Issued ?: return null
        if (issued.instances.isEmpty()) return null

        val picked = issued.instances.minByOrNull { it.useCount } ?: return null
        val updatedInstances = when (issued.policy.use) {
            KeyUse.Rotate -> issued.instances.map {
                if (it === picked) CredentialInstance(it.key, it.payload, it.useCount + 1) else it
            }
            KeyUse.OneTime -> issued.instances.filterNot { it === picked }
        }

        val updated = CredentialEnvelope(
            id = envelope.id,
            format = envelope.format,
            createdAt = envelope.createdAt,
            lifecycle = EnvelopeLifecycle.Issued(issued.policy, updatedInstances),
            metadata = envelope.metadata, // preserve issuer/display + trust flags across a presentation
        )
        driver.put(COLLECTION, updated.id.value, EnvelopeCodec.encode(updated))
        _changes.tryEmit(CredentialStoreChange.Updated(updated.id))

        ConsumedInstance(picked, remaining = updatedInstances.size)
    }
}
