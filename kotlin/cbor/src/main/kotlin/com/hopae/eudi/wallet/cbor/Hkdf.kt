package com.hopae.eudi.wallet.cbor

import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * HKDF-SHA256 (RFC 5869). The KDF ISO/IEC 18013-5 §9.1.1.4 uses for mdoc session keys and the
 * §9.1.3.5 `EMacKey`; shared by the `proximity` session layer and the `mdoc` `deviceMac` path.
 */
object Hkdf {

    fun deriveSha256(ikm: ByteArray, salt: ByteArray, info: ByteArray, length: Int): ByteArray {
        val prk = hmac(if (salt.isEmpty()) ByteArray(32) else salt, ikm) // extract
        val out = ByteArray(length)
        var t = ByteArray(0)
        var generated = 0
        var counter = 1
        while (generated < length) {
            t = hmac(prk, t + info + byteArrayOf(counter.toByte())) // expand
            val n = minOf(t.size, length - generated)
            t.copyInto(out, generated, 0, n)
            generated += n
            counter++
        }
        return out
    }

    private fun hmac(key: ByteArray, data: ByteArray): ByteArray =
        Mac.getInstance("HmacSHA256").apply { init(SecretKeySpec(key, "HmacSHA256")) }.doFinal(data)
}
