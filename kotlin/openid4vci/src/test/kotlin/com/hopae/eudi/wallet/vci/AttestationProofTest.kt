package com.hopae.eudi.wallet.vci

import com.hopae.eudi.wallet.sdjwt.JsonValue
import com.hopae.eudi.wallet.sdjwt.Jws
import com.hopae.eudi.wallet.sdjwt.JwkEc
import com.hopae.eudi.wallet.sdjwt.SecureAreaJwsSigner
import com.hopae.eudi.wallet.spi.KeyInfo
import com.hopae.eudi.wallet.spi.KeySpec
import com.hopae.eudi.wallet.spi.Rng
import com.hopae.eudi.wallet.spi.SigningAlgorithm
import com.hopae.eudi.wallet.testkit.SoftwareSecureArea
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull

/**
 * OpenID4VCI §8.2.1 Appendix F.3 `attestation` proof type: a single Key Attestation JWT (with
 * `attested_keys`) sent as the proof, without a per-key proof of possession. Used only when the issuer
 * advertises it and the wallet opts in; otherwise the `jwt` proof type is used.
 */
class AttestationProofTest {

    private val now = 1_700_000_000L
    private fun rng() = Rng { size -> ByteArray(size) { (it + 1).toByte() } }

    /** A Key Attestation source that attests [proofKeys] and binds the c_nonce (Appendix D.1). */
    private fun attestationSource(area: SoftwareSecureArea, attKey: KeyInfo, proofKeys: List<KeyInfo>) =
        KeyAttestationSource { cNonce ->
            val header = JsonValue.Obj(listOf("typ" to JsonValue.Str("keyattestation+jwt"), "alg" to JsonValue.Str("ES256")))
            val claims = JsonValue.Obj(
                buildList {
                    add("iat" to JsonValue.NumInt(now))
                    cNonce?.let { add("nonce" to JsonValue.Str(it)) }
                    add("attested_keys" to JsonValue.Arr(proofKeys.map { JwkEc.toJson(it.publicKey) }))
                }
            )
            Jws.sign(header, claims.serialize().encodeToByteArray(), SecureAreaJwsSigner(area, attKey.handle, SigningAlgorithm.ES256)).compact()
        }

    private fun keys(area: SoftwareSecureArea, proof: KeyInfo, dpop: KeyInfo) = IssuanceKeys(
        SecureAreaJwsSigner(area, proof.handle, SigningAlgorithm.ES256), proof.publicKey,
        SecureAreaJwsSigner(area, dpop.handle, SigningAlgorithm.ES256), dpop.publicKey,
    )

    @Test
    fun usesAttestationProofTypeWhenSupportedAndPreferred() = runBlocking {
        val area = SoftwareSecureArea()
        val issuerKey = area.createKey(KeySpec(secureArea = area.id, algorithm = SigningAlgorithm.ES256))
        val mock = MockIssuer(area, issuerKey, now).apply { supportsAttestationProof = true }
        val proof = area.createKey(KeySpec(secureArea = area.id, algorithm = SigningAlgorithm.ES256))
        val dpop = area.createKey(KeySpec(secureArea = area.id, algorithm = SigningAlgorithm.ES256))
        val attKey = area.createKey(KeySpec(secureArea = area.id, algorithm = SigningAlgorithm.ES256))
        val client = Openid4VciClient(
            mock, rng(), clock = { now },
            keyAttestation = attestationSource(area, attKey, listOf(proof)),
            preferAttestationProof = true,
        )

        val offer = CredentialOffer.parse(mock.credentialOfferJson)
        val response = client.issueWithPreAuthorizedCode(offer, "eu.europa.ec.eudi.pid.1", keys(area, proof, dpop), txCode = "1234")

        assertEquals(1, response.credentials.size, "one credential per attested key")
        assertNotNull(mock.seenAttestationProof, "the attestation proof type was used")
        assertNull(mock.seenKeyAttestation, "no jwt-proof header path when the attestation proof type is used")
    }

    @Test
    fun fallsBackToJwtProofWhenIssuerDoesNotSupportAttestation() = runBlocking {
        // preferAttestationProof is set, but the issuer advertises only the jwt proof type → jwt is used,
        // carrying the attestation in the proof header instead.
        val area = SoftwareSecureArea()
        val issuerKey = area.createKey(KeySpec(secureArea = area.id, algorithm = SigningAlgorithm.ES256))
        val mock = MockIssuer(area, issuerKey, now) // supportsAttestationProof stays false
        val proof = area.createKey(KeySpec(secureArea = area.id, algorithm = SigningAlgorithm.ES256))
        val dpop = area.createKey(KeySpec(secureArea = area.id, algorithm = SigningAlgorithm.ES256))
        val attKey = area.createKey(KeySpec(secureArea = area.id, algorithm = SigningAlgorithm.ES256))
        val client = Openid4VciClient(
            mock, rng(), clock = { now },
            keyAttestation = attestationSource(area, attKey, listOf(proof)),
            preferAttestationProof = true,
        )

        val offer = CredentialOffer.parse(mock.credentialOfferJson)
        client.issueWithPreAuthorizedCode(offer, "eu.europa.ec.eudi.pid.1", keys(area, proof, dpop), txCode = "1234")

        assertNull(mock.seenAttestationProof, "the attestation proof type is not used when unsupported")
        assertEquals(1, mock.seenProofCount, "a jwt proof was sent")
        assertNotNull(mock.seenKeyAttestation, "the attestation rides in the jwt proof header instead")
    }
}
