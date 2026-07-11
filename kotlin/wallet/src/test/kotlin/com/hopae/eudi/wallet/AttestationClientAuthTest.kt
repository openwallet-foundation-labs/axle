package com.hopae.eudi.wallet

import com.hopae.eudi.wallet.spi.KeyInfo
import com.hopae.eudi.wallet.spi.Rng
import com.hopae.eudi.wallet.spi.WalletAttestationProvider
import com.hopae.eudi.wallet.testkit.InMemoryStorageDriver
import com.hopae.eudi.wallet.testkit.SoftwareSecureArea
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull

class AttestationClientAuthTest {
    /** A WUA provider that hands out a distinct token per fetch, so reuse-vs-refresh is observable. */
    private class CountingProvider : WalletAttestationProvider {
        var fetches = 0
            private set
        override suspend fun walletAttestation(keyInfo: KeyInfo): String = "wua-${++fetches}"
        override suspend fun keyAttestation(keys: List<KeyInfo>, nonce: String?): String = "ka"
    }

    private fun wua(headers: List<Pair<String, String>>) = headers.first { it.first == "OAuth-Client-Attestation" }.second
    private fun pop(headers: List<Pair<String, String>>) = headers.first { it.first == "OAuth-Client-Attestation-PoP" }.second

    @Test
    fun `fresh WUA per issuer, reused within an issuer, fresh PoP per request`() = runBlocking {
        val provider = CountingProvider()
        val auth = AttestationClientAuth(
            clientId = "wallet-dev",
            provider = provider,
            secureArea = SoftwareSecureArea(),
            storage = InMemoryStorageDriver(),
            rng = Rng.Default,
            clock = { 1000L },
        )

        val a1 = auth.headers("https://issuer-a")
        val a2 = auth.headers("https://issuer-a") // same issuer → reuse the WUA
        val b = auth.headers("https://issuer-b")  // different issuer → fresh WUA (never reused across issuers)

        assertEquals(listOf("OAuth-Client-Attestation", "OAuth-Client-Attestation-PoP"), a1.map { it.first })
        // HAIP §4.4.1: one WUA per issuer — A's two calls share wua-1, B gets wua-2 → 2 fetches, not 3.
        assertEquals(2, provider.fetches)
        assertEquals("wua-1", wua(a1))
        assertEquals("wua-1", wua(a2))
        assertEquals("wua-2", wua(b))
        // The PoP is fresh every request even for the same issuer (distinct jti).
        assertNotEquals(pop(a1), pop(a2))
    }

    @Test
    fun `instance key is created once and persisted`() = runBlocking {
        val area = SoftwareSecureArea()
        val storage = InMemoryStorageDriver()
        val provider = CountingProvider()
        AttestationClientAuth("wallet-dev", provider, area, storage, Rng.Default, { 1L }).headers("https://issuer")

        // The instance key's alias is remembered so the same cnf key is reused across restarts.
        assertNotNull(storage.get("wallet-provider", "instance-key"))
        // A second provider over the same secure area + storage reloads that key (no crash, headers produced).
        val reloaded = AttestationClientAuth("wallet-dev", provider, area, storage, Rng.Default, { 1L }).headers("https://issuer")
        assertNotNull(wua(reloaded))
    }
}
