package com.hopae.eudi.wallet.vci

import com.hopae.eudi.wallet.sdjwt.JsonValue
import com.hopae.eudi.wallet.sdjwt.Jws
import com.hopae.eudi.wallet.sdjwt.SecureAreaJwsSigner
import com.hopae.eudi.wallet.spi.HttpRequest
import com.hopae.eudi.wallet.spi.HttpResponse
import com.hopae.eudi.wallet.spi.HttpTransport
import com.hopae.eudi.wallet.spi.KeyInfo
import com.hopae.eudi.wallet.spi.KeySpec
import com.hopae.eudi.wallet.spi.Rng
import com.hopae.eudi.wallet.spi.SigningAlgorithm
import com.hopae.eudi.wallet.spi.WalletAttestationProvider
import com.hopae.eudi.wallet.testkit.SoftwareSecureArea
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/** HAIP attestation-based client authentication: PAR + token requests carry the client attestation. */
class ClientAttestationTest {

    private val now = 1_700_000_000L
    private fun rng() = Rng { size -> ByteArray(size) { (it + 1).toByte() } }

    private class Capturing(private val delegate: HttpTransport) : HttpTransport {
        val requests = mutableListOf<HttpRequest>()
        override suspend fun execute(request: HttpRequest): HttpResponse {
            requests.add(request)
            return delegate.execute(request)
        }
    }

    private fun fakeProvider() = object : WalletAttestationProvider {
        override suspend fun walletAttestation(keyInfo: KeyInfo): String = "eyJ.attestation.jwt"
        override suspend fun keyAttestation(keys: List<KeyInfo>, nonce: String?): String = "eyJ.key.jwt"
    }

    private fun header(request: HttpRequest, name: String): String? =
        request.headers.firstOrNull { it.first == name }?.second

    @Test
    fun clientAttestationOnParAndToken() = runBlocking {
        val area = SoftwareSecureArea()
        val issuerKey = area.createKey(KeySpec(secureArea = area.id, algorithm = SigningAlgorithm.ES256))
        val mock = MockIssuer(area, issuerKey, now) // stateful (PAR request_uri) — same instance for the whole flow
        val capturing = Capturing(mock)

        val proofKey = area.createKey(KeySpec(secureArea = area.id, algorithm = SigningAlgorithm.ES256))
        val dpopKey = area.createKey(KeySpec(secureArea = area.id, algorithm = SigningAlgorithm.ES256))
        val instanceKey = area.createKey(KeySpec(secureArea = area.id, algorithm = SigningAlgorithm.ES256))
        val keys = IssuanceKeys(
            SecureAreaJwsSigner(area, proofKey.handle, SigningAlgorithm.ES256), proofKey.publicKey,
            SecureAreaJwsSigner(area, dpopKey.handle, SigningAlgorithm.ES256), dpopKey.publicKey,
        )
        val clientAuth = WalletClientAuth.create(
            fakeProvider(), instanceKey, SecureAreaJwsSigner(area, instanceKey.handle, SigningAlgorithm.ES256),
            clientId = "wallet-instance-1", rng = rng(), clock = { now },
        )
        val client = Openid4VciClient(capturing, rng(), clock = { now }, clientAuth = clientAuth)

        val prepared = client.prepareAuthorizationCodeIssuance("https://issuer.example", "eu.europa.ec.eudi.pid.1", "wallet://cb")
        // emulate the browser hitting the authorization URL on the same mock instance -> code
        val redirect = mock.execute(HttpRequest(com.hopae.eudi.wallet.spi.HttpMethod.GET, prepared.authorizationUrl))
        val code = redirect.headers.first { it.first == "Location" }.second.substringAfter("code=").substringBefore('&')
        client.finishAuthorizationCodeIssuance(prepared, code, keys)

        // PAR and token requests must both carry the attestation + a valid PoP
        for (path in listOf("/par", "/token")) {
            val req = capturing.requests.last { it.url.endsWith(path) }
            assertEquals("eyJ.attestation.jwt", header(req, "OAuth-Client-Attestation"), "attestation on $path")
            val jws = Jws.parse(header(req, "OAuth-Client-Attestation-PoP") ?: error("no PoP on $path"))
            assertEquals("oauth-client-attestation-pop+jwt", (jws.header["typ"] as JsonValue.Str).value)
            val payload = JsonValue.parse(jws.payloadBytes.decodeToString()) as JsonValue.Obj
            assertEquals("wallet-instance-1", (payload["iss"] as JsonValue.Str).value, "PoP iss on $path")
            assertEquals("https://issuer.example", (payload["aud"] as JsonValue.Str).value, "PoP aud on $path")
            assertTrue(jws.verify(instanceKey.publicKey, SigningAlgorithm.ES256), "PoP signature on $path")
        }
    }

    @Test
    fun popJwtStructure() = runBlocking {
        val area = SoftwareSecureArea()
        val key = area.createKey(KeySpec(secureArea = area.id, algorithm = SigningAlgorithm.ES256))
        val pop = ClientAttestationPop(SecureAreaJwsSigner(area, key.handle, SigningAlgorithm.ES256), "client-x", rng(), { now })
        val jws = Jws.parse(pop.pop("https://as.example"))
        val payload = JsonValue.parse(jws.payloadBytes.decodeToString()) as JsonValue.Obj
        assertEquals("client-x", (payload["iss"] as JsonValue.Str).value)
        assertEquals("https://as.example", (payload["aud"] as JsonValue.Str).value)
        assertEquals(now + 300, (payload["exp"] as JsonValue.NumInt).value)
        assertTrue((payload["jti"] as JsonValue.Str).value.isNotEmpty())
        assertTrue(jws.verify(key.publicKey, SigningAlgorithm.ES256))
    }
}
