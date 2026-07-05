package com.hopae.eudi.wallet.vci

import com.hopae.eudi.wallet.sdjwt.JsonValue
import com.hopae.eudi.wallet.sdjwt.Jws
import com.hopae.eudi.wallet.sdjwt.SecureAreaJwsSigner
import com.hopae.eudi.wallet.spi.KeyInfo
import com.hopae.eudi.wallet.spi.KeySpec
import com.hopae.eudi.wallet.spi.Rng
import com.hopae.eudi.wallet.spi.SigningAlgorithm
import com.hopae.eudi.wallet.testkit.SoftwareSecureArea
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/** Minor HAIP gaps: refresh-token reissuance (RFC 6749 §6) and signed issuer metadata (§11.2.3). */
class RefreshSignedMetadataTest {

    private val now = 1_700_000_000L
    private fun rng() = Rng { size -> ByteArray(size) { (it + 1).toByte() } }

    private suspend fun keys(area: SoftwareSecureArea): IssuanceKeys {
        val proofKey = area.createKey(KeySpec(secureArea = area.id, algorithm = SigningAlgorithm.ES256))
        val dpopKey = area.createKey(KeySpec(secureArea = area.id, algorithm = SigningAlgorithm.ES256))
        return IssuanceKeys(
            SecureAreaJwsSigner(area, proofKey.handle, SigningAlgorithm.ES256), proofKey.publicKey,
            SecureAreaJwsSigner(area, dpopKey.handle, SigningAlgorithm.ES256), dpopKey.publicKey,
        )
    }

    @Test
    fun reissueWithRefreshToken() = runBlocking {
        val area = SoftwareSecureArea()
        val issuerKey = area.createKey(KeySpec(secureArea = area.id, algorithm = SigningAlgorithm.ES256))
        val mock = MockIssuer(area, issuerKey, now)
        val client = Openid4VciClient(mock, rng(), clock = { now })

        val offer = CredentialOffer.parse(mock.credentialOfferJson)
        val first = client.issueWithPreAuthorizedCode(offer, "eu.europa.ec.eudi.pid.1", keys(area), txCode = "1234")
        assertEquals(1, first.credentials.size)
        assertTrue(first.canReissue, "issuer granted a refresh token")

        // renew with rotated holder keys — no browser re-authorization
        val renewed = client.reissue(first, keys(area))
        assertEquals(1, renewed.credentials.size)
        assertTrue(renewed.canReissue, "renewed response carries a fresh refresh token")
    }

    /** Verifier: checks the signed_metadata JWS against the issuer key, returns its claims. */
    private fun verifier(area: SoftwareSecureArea, issuerKey: KeyInfo) = SignedMetadataVerifier { jws ->
        val parsed = Jws.parse(jws)
        require(parsed.verify(issuerKey.publicKey, SigningAlgorithm.ES256)) { "bad signed_metadata signature" }
        JsonValue.parse(parsed.payloadBytes.decodeToString()) as JsonValue.Obj
    }

    private suspend fun signMetadata(area: SoftwareSecureArea, issuerKey: KeyInfo, payload: JsonValue.Obj): String {
        val header = JsonValue.Obj(listOf("alg" to JsonValue.Str("ES256"), "typ" to JsonValue.Str("jwt")))
        return Jws.sign(header, payload.serialize().encodeToByteArray(), SecureAreaJwsSigner(area, issuerKey.handle, SigningAlgorithm.ES256)).compact()
    }

    @Test
    fun requireSignedUsesVerifiedMetadata() = runBlocking {
        val area = SoftwareSecureArea()
        val issuerKey = area.createKey(KeySpec(secureArea = area.id, algorithm = SigningAlgorithm.ES256))
        val mock = MockIssuer(area, issuerKey, now)
        // signed_metadata authoritatively pins the nonce endpoint
        mock.signedMetadata = signMetadata(area, issuerKey, JsonValue.Obj(listOf(
            "credential_issuer" to JsonValue.Str("https://issuer.example"),
            "nonce_endpoint" to JsonValue.Str("https://issuer.example/signed-nonce"),
        )))
        val client = Openid4VciClient(mock, rng(), clock = { now }, metadataPolicy = IssuerMetadataPolicy.RequireSigned(verifier(area, issuerKey)))

        val meta = client.loadIssuerMetadata("https://issuer.example")
        assertEquals("https://issuer.example", meta.credentialIssuer)
        assertEquals("https://issuer.example/signed-nonce", meta.nonceEndpoint) // verified claim overrode the fetched JSON
    }

    @Test
    fun requireSignedRejectsUnsignedMetadata() = runBlocking<Unit> {
        val area = SoftwareSecureArea()
        val issuerKey = area.createKey(KeySpec(secureArea = area.id, algorithm = SigningAlgorithm.ES256))
        val mock = MockIssuer(area, issuerKey, now) // no signedMetadata set
        val client = Openid4VciClient(mock, rng(), clock = { now }, metadataPolicy = IssuerMetadataPolicy.RequireSigned(verifier(area, issuerKey)))

        assertFailsWith<VciException.MetadataError> { client.loadIssuerMetadata("https://issuer.example") }
    }

    @Test
    fun requireSignedRejectsBadSignature() = runBlocking<Unit> {
        val area = SoftwareSecureArea()
        val issuerKey = area.createKey(KeySpec(secureArea = area.id, algorithm = SigningAlgorithm.ES256))
        val rogue = area.createKey(KeySpec(secureArea = area.id, algorithm = SigningAlgorithm.ES256))
        val mock = MockIssuer(area, issuerKey, now)
        mock.signedMetadata = signMetadata(area, rogue, JsonValue.Obj(listOf("credential_issuer" to JsonValue.Str("https://issuer.example"))))
        val client = Openid4VciClient(mock, rng(), clock = { now }, metadataPolicy = IssuerMetadataPolicy.RequireSigned(verifier(area, issuerKey)))

        assertFailsWith<IllegalArgumentException> { client.loadIssuerMetadata("https://issuer.example") }
    }
}
