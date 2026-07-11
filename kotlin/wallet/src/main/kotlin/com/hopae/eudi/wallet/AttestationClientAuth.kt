package com.hopae.eudi.wallet

import com.hopae.eudi.wallet.sdjwt.SecureAreaJwsSigner
import com.hopae.eudi.wallet.spi.KeyHandle
import com.hopae.eudi.wallet.spi.KeyInfo
import com.hopae.eudi.wallet.spi.KeySpec
import com.hopae.eudi.wallet.spi.Rng
import com.hopae.eudi.wallet.spi.SecureArea
import com.hopae.eudi.wallet.spi.SigningAlgorithm
import com.hopae.eudi.wallet.spi.StorageDriver
import com.hopae.eudi.wallet.spi.WalletAttestationProvider
import com.hopae.eudi.wallet.vci.ClientAttestationPop
import com.hopae.eudi.wallet.vci.ClientAuthProvider
import com.hopae.eudi.wallet.vci.WalletClientAuth
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

/**
 * HAIP attestation-based client authentication, wired from [WalletPorts.walletAttestation]. Holds one
 * persistent **wallet instance key** (created in the [secureArea] and remembered via [storage]; bound into
 * every WUA's `cnf`) and, on each request, produces the `OAuth-Client-Attestation[-PoP]` headers.
 *
 * HAIP §4.4.1 (unlinkability): a WUA is fetched **fresh per authorization server** and **never reused across
 * issuers** — [wuaByAudience] caches one WUA per `aud` so a single issuer's PAR + token reuse it, but a
 * different issuer always triggers a fresh fetch. The `sub` is the (non-instance-unique) [clientId].
 *
 * Residual (documented, not fixed here): because the instance key is persistent, the WUA `cnf` is the same
 * across issuers, so colluding issuers could still correlate via the key. Full unlinkability needs a per-use
 * key batch (HAIP wallet attestation batch) — a later refinement.
 */
internal class AttestationClientAuth(
    override val clientId: String,
    private val provider: WalletAttestationProvider,
    private val secureArea: SecureArea,
    private val storage: StorageDriver,
    private val rng: Rng,
    private val clock: () -> Long,
) : ClientAuthProvider {

    private val keyMutex = Mutex()
    private val wuaMutex = Mutex()
    private var instance: KeyInfo? = null
    private val wuaByAudience = mutableMapOf<String, String>()

    override suspend fun headers(audience: String): List<Pair<String, String>> {
        val key = instanceKey()
        val wua = walletAttestation(audience, key)
        val pop = ClientAttestationPop(SecureAreaJwsSigner(secureArea, key.handle, key.algorithm), clientId, rng, clock)
        return WalletClientAuth(clientId, wua, pop).headers(audience)
    }

    /** The persistent wallet instance key: created once, its alias remembered so it survives restarts. */
    private suspend fun instanceKey(): KeyInfo = keyMutex.withLock {
        instance?.let { return it }
        val stored = storage.get(COLLECTION, INSTANCE_KEY)
        val info = if (stored != null) {
            val handle = KeyHandle(secureArea.id, stored.decodeToString())
            KeyInfo(handle, SigningAlgorithm.ES256, secureArea.publicKey(handle))
        } else {
            secureArea.createKey(KeySpec(secureArea = secureArea.id)).also {
                storage.put(COLLECTION, INSTANCE_KEY, it.handle.alias.encodeToByteArray())
            }
        }
        instance = info
        info
    }

    private suspend fun walletAttestation(audience: String, key: KeyInfo): String = wuaMutex.withLock {
        wuaByAudience[audience] ?: provider.walletAttestation(key).also { wuaByAudience[audience] = it }
    }

    private companion object {
        const val COLLECTION = "wallet-provider"
        const val INSTANCE_KEY = "instance-key"
    }
}
