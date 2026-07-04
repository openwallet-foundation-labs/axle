package com.hopae.eudi.wallet.spi

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class SpiSmokeTest {

    @Test
    fun keySpecDefaultsMatchContract() {
        val spec = KeySpec()
        assertEquals(SecureAreaId.Default, spec.secureArea)
        assertEquals(SigningAlgorithm.ES256, spec.algorithm)
        assertEquals(UserAuthPolicy.NotRequired, spec.userAuthentication)
        assertEquals(HardwarePolicy.Preferred, spec.hardware)
    }

    @Test
    fun credentialPolicyDefaultsMatchContract() {
        val policy = CredentialPolicy()
        assertEquals(1, policy.batchSize)
        assertEquals(KeyUse.Rotate, policy.use)
    }

    @Test
    fun runtimeDefaultsWork() {
        assertNotNull(WalletClock.System.now())
        val bytes = Rng.Default.nextBytes(16)
        assertEquals(16, bytes.size)
        assertTrue(bytes.any { it != 0.toByte() }, "16 random bytes should not be all zero")
    }
}
