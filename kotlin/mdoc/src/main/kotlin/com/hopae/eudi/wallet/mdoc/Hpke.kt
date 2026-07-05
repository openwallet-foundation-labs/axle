package com.hopae.eudi.wallet.mdoc

import com.hopae.eudi.wallet.cbor.cose.EcPublicKey
import com.hopae.eudi.wallet.cbor.cose.Ecdsa
import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPrivateKeySpec
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * HPKE (RFC 9180) — base mode, cipher suite DHKEM(P-256, HKDF-SHA256) / HKDF-SHA256 / AES-128-GCM.
 * This is the suite the ISO/IEC 18013-7:2025 Annex C Digital Credentials API uses to encrypt the mdoc
 * `DeviceResponse` to the verifier's ephemeral `recipientPublicKey`. Only single-shot sealing is needed.
 */
object Hpke {
    private const val KEM_ID = 0x0010 // DHKEM(P-256, HKDF-SHA256)
    private const val KDF_ID = 0x0001 // HKDF-SHA256
    private const val AEAD_ID = 0x0001 // AES-128-GCM
    private const val NSECRET = 32 // KEM shared secret
    private const val NK = 16 // AES-128 key
    private const val NN = 12 // GCM nonce
    private const val NH = 32 // SHA-256 output

    /** The `enc` (encapsulated ephemeral public key, uncompressed) and the AEAD `ciphertext` (incl. tag). */
    class Sealed(val enc: ByteArray, val ciphertext: ByteArray)

    /** Seals [plaintext] to [recipient] with the given HPKE `info`/`aad`. [ephemeral] is injectable for test vectors. */
    fun sealBaseP256(
        recipient: EcPublicKey,
        info: ByteArray,
        aad: ByteArray,
        plaintext: ByteArray,
        ephemeral: Ephemeral = Ephemeral.random(),
    ): Sealed {
        val recipientPub = Ecdsa.publicKeyOf(recipient) as ECPublicKey
        val dh = KeyAgreement.getInstance("ECDH").run {
            init(ephemeral.privateKey)
            doPhase(recipientPub, true)
            generateSecret() // P-256 ECDH → 32-byte X coordinate
        }
        val enc = serialize(ephemeral.publicPoint)
        val kemContext = enc + serialize(recipientPub.w)

        val sharedSecret = extractAndExpand(kemSuiteId(), dh, kemContext, NSECRET)

        val pskIdHash = labeledExtract(hpkeSuiteId(), null, "psk_id_hash", ByteArray(0))
        val infoHash = labeledExtract(hpkeSuiteId(), null, "info_hash", info)
        val ksContext = byteArrayOf(0) + pskIdHash + infoHash // base mode
        val secret = labeledExtract(hpkeSuiteId(), sharedSecret, "secret", ByteArray(0))
        val key = labeledExpand(hpkeSuiteId(), secret, "key", ksContext, NK)
        val baseNonce = labeledExpand(hpkeSuiteId(), secret, "base_nonce", ksContext, NN)

        // Single-shot: sequence number 0, so the per-message nonce equals base_nonce.
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, baseNonce))
        cipher.updateAAD(aad)
        return Sealed(enc, cipher.doFinal(plaintext))
    }

    // ---- RFC 9180 §4 labeled KDF ----

    private fun kemSuiteId() = "KEM".toByteArray() + i2osp(KEM_ID, 2)
    private fun hpkeSuiteId() = "HPKE".toByteArray() + i2osp(KEM_ID, 2) + i2osp(KDF_ID, 2) + i2osp(AEAD_ID, 2)

    private fun labeledExtract(suiteId: ByteArray, salt: ByteArray?, label: String, ikm: ByteArray): ByteArray {
        val labeledIkm = "HPKE-v1".toByteArray() + suiteId + label.toByteArray() + ikm
        return hkdfExtract(salt, labeledIkm)
    }

    private fun labeledExpand(suiteId: ByteArray, prk: ByteArray, label: String, info: ByteArray, length: Int): ByteArray {
        val labeledInfo = i2osp(length, 2) + "HPKE-v1".toByteArray() + suiteId + label.toByteArray() + info
        return hkdfExpand(prk, labeledInfo, length)
    }

    private fun extractAndExpand(suiteId: ByteArray, dh: ByteArray, kemContext: ByteArray, length: Int): ByteArray {
        val eaePrk = labeledExtract(suiteId, null, "eae_prk", dh)
        return labeledExpand(suiteId, eaePrk, "shared_secret", kemContext, length)
    }

    // ---- HKDF-SHA256 (RFC 5869) ----

    private fun hkdfExtract(salt: ByteArray?, ikm: ByteArray): ByteArray = hmac(salt ?: ByteArray(NH), ikm)

    private fun hkdfExpand(prk: ByteArray, info: ByteArray, length: Int): ByteArray {
        val out = ByteArrayOutputStream()
        var t = ByteArray(0)
        var i = 1
        while (out.size() < length) {
            t = hmac(prk, t + info + byteArrayOf(i.toByte()))
            out.write(t)
            i++
        }
        return out.toByteArray().copyOf(length)
    }

    private fun hmac(key: ByteArray, data: ByteArray): ByteArray = Mac.getInstance("HmacSHA256").run {
        // JCA rejects an all-zero-length key; an all-zero 32-byte key is the RFC 5869 default salt anyway.
        init(SecretKeySpec(if (key.isEmpty()) ByteArray(NH) else key, "HmacSHA256"))
        doFinal(data)
    }

    // ---- P-256 point (de)serialization ----

    private fun serialize(point: ECPoint): ByteArray =
        byteArrayOf(0x04) + fixed(point.affineX, 32) + fixed(point.affineY, 32)

    private fun fixed(v: BigInteger, size: Int): ByteArray {
        val s = v.toByteArray().let { if (it.size > size) it.copyOfRange(it.size - size, it.size) else it }
        return ByteArray(size - s.size) + s
    }

    /** An HPKE ephemeral P-256 key pair; random in production, injectable for RFC test vectors. */
    class Ephemeral private constructor(val privateKey: ECPrivateKey, val publicPoint: ECPoint) {
        companion object {
            fun random(): Ephemeral {
                val kp = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
                return Ephemeral(kp.private as ECPrivateKey, (kp.public as ECPublicKey).w)
            }

            /** For test vectors: an ephemeral built from a raw private scalar + its public point. */
            internal fun of(scalar: ByteArray, publicPoint: ECPoint): Ephemeral {
                val params = AlgorithmParameters.getInstance("EC").apply { init(ECGenParameterSpec("secp256r1")) }
                    .getParameterSpec(ECParameterSpec::class.java)
                val priv = KeyFactory.getInstance("EC").generatePrivate(ECPrivateKeySpec(BigInteger(1, scalar), params)) as ECPrivateKey
                return Ephemeral(priv, publicPoint)
            }
        }
    }

    private fun i2osp(value: Int, length: Int): ByteArray {
        val out = ByteArray(length)
        var v = value
        for (i in length - 1 downTo 0) { out[i] = (v and 0xFF).toByte(); v = v ushr 8 }
        return out
    }
}
