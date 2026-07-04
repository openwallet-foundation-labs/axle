package com.hopae.eudi.wallet.sdjwt

import com.hopae.eudi.wallet.cbor.cose.EcCurve
import com.hopae.eudi.wallet.cbor.cose.EcPublicKey
import java.math.BigInteger
import java.security.KeyPairGenerator
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class JweTest {

    private fun fixed(b: BigInteger, size: Int): ByteArray {
        val s = b.toByteArray().dropWhile { it == 0.toByte() }.toByteArray()
        return ByteArray(size - s.size) + s
    }

    @Test
    fun concatKdfMatchesRfc7518AppendixC() {
        // RFC 7518 Appendix C — ECDH-ES key agreement worked example.
        val z = intArrayOf(
            158, 86, 217, 29, 129, 113, 53, 211, 114, 131, 66, 131, 191, 132, 38, 156,
            251, 49, 110, 163, 218, 128, 106, 72, 246, 218, 167, 121, 140, 254, 144, 196,
        ).map { it.toByte() }.toByteArray()
        val derived = Jwe.concatKdf(z, 128, "A128GCM", "Alice".encodeToByteArray(), "Bob".encodeToByteArray())
        // expected derived key: base64url "VqqN6vgjbSBcIijNcacQGg"
        assertEquals("VqqN6vgjbSBcIijNcacQGg", Base64Url.encode(derived))
    }

    @Test
    fun encryptDecryptRoundtrip() {
        for (enc in listOf(JweEnc.A128GCM, JweEnc.A256GCM)) {
            val kp = KeyPairGenerator.getInstance("EC")
                .apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
            val pub = kp.public as ECPublicKey
            val recipient = EcPublicKey(EcCurve.P256, fixed(pub.w.affineX, 32), fixed(pub.w.affineY, 32))
            val d = fixed((kp.private as ECPrivateKey).s, 32)

            val plaintext = """{"vp_token":{"pid":"eyJ...~"},"state":"abc"}""".encodeToByteArray()
            val jwe = Jwe.encryptEcdhEs(plaintext, recipient, enc, apu = "wallet".encodeToByteArray())
            assertEquals(5, jwe.split('.').size)
            assertEquals("", jwe.split('.')[1], "ECDH-ES direct has empty encrypted_key")

            val decrypted = Jwe.decryptEcdhEs(jwe, d, EcCurve.P256)
            assertContentEquals(plaintext, decrypted)
        }
    }

    @Test
    fun tamperedCiphertextFails() {
        val kp = KeyPairGenerator.getInstance("EC")
            .apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
        val pub = kp.public as ECPublicKey
        val recipient = EcPublicKey(EcCurve.P256, fixed(pub.w.affineX, 32), fixed(pub.w.affineY, 32))
        val d = fixed((kp.private as ECPrivateKey).s, 32)

        val jwe = Jwe.encryptEcdhEs("secret".encodeToByteArray(), recipient)
        val parts = jwe.split('.').toMutableList()
        val ct = Base64Url.decode(parts[3]).also { it[0] = (it[0] + 1).toByte() }
        parts[3] = Base64Url.encode(ct)
        assertFailsWith<Exception> { Jwe.decryptEcdhEs(parts.joinToString("."), d, EcCurve.P256) }
    }
}
