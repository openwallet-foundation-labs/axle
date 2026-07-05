package com.hopae.eudi.wallet

import com.hopae.eudi.wallet.spi.CredentialPolicy
import com.hopae.eudi.wallet.spi.KeySpec
import com.hopae.eudi.wallet.spi.KeyUse
import com.hopae.eudi.wallet.spi.SigningAlgorithm
import com.hopae.eudi.wallet.testkit.InMemoryStorageDriver
import com.hopae.eudi.wallet.testkit.SoftwareSecureArea
import com.hopae.eudi.wallet.vci.MockIssuer
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/** Phase B slice 1: pre-authorized code issuance through the facade session → stored credential. */
class WalletIssuanceTest {

    @Test
    fun preAuthorizedIssuanceStoresCredential() = runBlocking {
        val area = SoftwareSecureArea()
        val issuerKey = area.createKey(KeySpec(secureArea = area.id, algorithm = SigningAlgorithm.ES256))
        val mock = MockIssuer(area, issuerKey, now = 1_700_000_000L)
        val wallet = Wallet.create(WalletConfig(), WalletPorts(listOf(area), InMemoryStorageDriver(), mock))

        val offer = wallet.issuance.resolveOffer(mock.credentialOfferJson)
        assertTrue(offer.requiresTxCode)

        val session = wallet.issuance.start(
            IssuanceRequest.fromOffer(offer, "eu.europa.ec.eudi.pid.1", txCode = "1234", policy = CredentialPolicy(batchSize = 2, use = KeyUse.OneTime)),
        )
        val terminal = withTimeout(15_000) { session.state.first { it.isTerminal } }
        assertTrue(terminal is IssuanceState.Completed, "expected Completed, got $terminal")
        val result = (terminal as IssuanceState.Completed).result
        assertEquals(1, result.issued.size)

        // the credential is now stored and visible via the credentials service
        val creds = wallet.credentials.list()
        assertEquals(1, creds.size)
        assertEquals(result.issued.single(), creds.single().id)
        val issued = creds.single().lifecycle as Lifecycle.Issued
        assertEquals(2, issued.instances.remaining, "batchSize=2 → 2 one-time instances")
        assertEquals(KeyUse.OneTime, issued.instances.use)
        assertTrue(issued.claims.any { it.path == listOf("given_name") && it.value.display() == "John" }, "PID given_name")

        wallet.close()
    }
}
