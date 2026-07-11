package com.hopae.eudi.wallet.android.attestation

import com.hopae.eudi.wallet.sdjwt.Base64Url
import com.hopae.eudi.wallet.sdjwt.JsonValue
import com.hopae.eudi.wallet.spi.HttpRequest
import com.hopae.eudi.wallet.spi.HttpResponse
import com.hopae.eudi.wallet.spi.HttpTransport
import com.hopae.eudi.wallet.spi.KeySpec
import com.hopae.eudi.wallet.testkit.SoftwareSecureArea
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * Server-independent unit test of the reference adapter's HTTP dance — a fake [HttpTransport] canned to look
 * like the wallet-provider backend. Runs in normal `./gradlew test` (no server, no `EUDI_WP_LIVE`); the live
 * integration test is the opt-in extra.
 */
class WalletProviderAttestationOfflineTest {
    private class FakeBackend : HttpTransport {
        val requests = mutableListOf<HttpRequest>()
        private var nonces = 0
        override suspend fun execute(request: HttpRequest): HttpResponse {
            requests += request
            val json = when {
                request.url.endsWith("/nonce") -> """{"nonce":"n${++nonces}"}"""
                request.url.endsWith("/wallet-instances") -> """{"instanceId":"inst-1"}"""
                request.url.endsWith("/wallet-attestation") -> """{"wallet_attestation":"header.payload.sig"}"""
                request.url.endsWith("/key-attestation") -> """{"key_attestation":"ka.ka.ka"}"""
                else -> return HttpResponse(404, emptyList(), ByteArray(0))
            }
            return HttpResponse(200, listOf("content-type" to "application/json"), json.encodeToByteArray())
        }

        fun bodyOf(path: String): JsonValue.Obj =
            JsonValue.parse(requests.first { it.url.endsWith(path) }.body!!.decodeToString()) as JsonValue.Obj

        fun paths(base: String) = requests.map { it.url.removePrefix(base) }
    }

    @Test
    fun `registers once, then fetches a WUA with a signed instance-key PoP`() = runBlocking {
        val area = SoftwareSecureArea()
        val key = area.createKey(KeySpec(secureArea = area.id))
        val backend = FakeBackend()
        val provider = WalletProviderAttestation("http://wp.test", backend, area, DevIntegrityTokenProvider(), "wallet-dev")

        val wua = provider.walletAttestation(key)
        assertEquals("header.payload.sig", wua)

        // The Type-4-like sequence: nonce → register → nonce → wallet-attestation.
        assertEquals(listOf("/nonce", "/wallet-instances", "/nonce", "/wallet-attestation"), backend.paths("http://wp.test"))

        // Registration carried the dev integrity token (bound to the first nonce) and the instance-key JWK.
        val register = backend.bodyOf("/wallet-instances")
        assertEquals("dev-integrity:n1", (register["integrityToken"] as JsonValue.Str).value)
        assertEquals(Base64Url.encode(key.publicKey.x), ((register["instanceKey"] as JsonValue.Obj)["x"] as JsonValue.Str).value)

        // wallet-attestation carried the instanceId, the (non-instance-unique) clientId, and a 3-part PoP JWT.
        val attest = backend.bodyOf("/wallet-attestation")
        assertEquals("inst-1", (attest["instanceId"] as JsonValue.Str).value)
        assertEquals("wallet-dev", (attest["clientId"] as JsonValue.Str).value)
        assertEquals(3, (attest["pop"] as JsonValue.Str).value.split(".").size)

        // A second WUA reuses the cached registration — no second POST /wallet-instances.
        provider.walletAttestation(key)
        assertEquals(1, backend.requests.count { it.url.endsWith("/wallet-instances") })
    }
}
