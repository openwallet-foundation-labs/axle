package com.hopae.eudi.wallet.vci

import com.hopae.eudi.wallet.sdjwt.SecureAreaJwsSigner
import com.hopae.eudi.wallet.spi.KeySpec
import com.hopae.eudi.wallet.spi.Rng
import com.hopae.eudi.wallet.spi.SigningAlgorithm
import com.hopae.eudi.wallet.testkit.SoftwareSecureArea
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

/**
 * OpenID4VCI §8.2 `credential_identifiers`: when the token-response `authorization_details` bind concrete
 * dataset identifiers to a config, the Credential Request MUST carry a `credential_identifier` and MUST NOT
 * carry `credential_configuration_id`; otherwise it uses `credential_configuration_id`.
 */
class CredentialIdentifiersTest {

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
    fun requestsWithCredentialIdentifierWhenTokenBindsThem() = runBlocking {
        val area = SoftwareSecureArea()
        val issuerKey = area.createKey(KeySpec(secureArea = area.id, algorithm = SigningAlgorithm.ES256))
        val mock = MockIssuer(area, issuerKey, now).apply {
            credentialIdentifiers = listOf("pid-dataset-1", "pid-dataset-2")
        }
        val client = Openid4VciClient(mock, rng(), clock = { now })

        val offer = CredentialOffer.parse(mock.credentialOfferJson)
        val response = client.issueWithPreAuthorizedCode(offer, "eu.europa.ec.eudi.pid.1", keys(area), txCode = "1234")

        assertEquals(1, response.credentials.size, "the credential is issued for the chosen dataset")
        // The request identified the dataset by the first credential_identifier, with no credential_configuration_id.
        assertEquals("pid-dataset-1", mock.seenCredentialIdentifier)
        assertNull(mock.seenConfigurationId, "credential_configuration_id MUST NOT be sent alongside a credential_identifier")
    }

    @Test
    fun requestsWithConfigurationIdWhenTokenBindsNoIdentifiers() = runBlocking {
        // No authorization_details in the token response (e.g. scope-based authorization) → configuration id.
        val area = SoftwareSecureArea()
        val issuerKey = area.createKey(KeySpec(secureArea = area.id, algorithm = SigningAlgorithm.ES256))
        val mock = MockIssuer(area, issuerKey, now)
        val client = Openid4VciClient(mock, rng(), clock = { now })

        val offer = CredentialOffer.parse(mock.credentialOfferJson)
        client.issueWithPreAuthorizedCode(offer, "eu.europa.ec.eudi.pid.1", keys(area), txCode = "1234")

        assertEquals("eu.europa.ec.eudi.pid.1", mock.seenConfigurationId)
        assertNull(mock.seenCredentialIdentifier)
    }
}
