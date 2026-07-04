package com.hopae.eudi.wallet.proximity

import com.hopae.eudi.wallet.cbor.cose.EcCurve
import com.hopae.eudi.wallet.cbor.cose.EcPublicKey
import java.math.BigInteger
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

class ProximityException(message: String) : Exception(message)

/** An ephemeral P-256 key pair for mdoc session establishment (EDeviceKey / EReaderKey). */
class EphemeralKeyPair private constructor(private val keyPair: KeyPair) {

    val publicKey: EcPublicKey
        get() {
            val pub = keyPair.public as ECPublicKey
            return EcPublicKey(EcCurve.P256, fixed(pub.w.affineX), fixed(pub.w.affineY))
        }

    /** Raw ECDH shared secret (Zab) with the peer's ephemeral key. */
    fun sharedSecret(peer: EcPublicKey): ByteArray = KeyAgreement.getInstance("ECDH").run {
        init(keyPair.private)
        doPhase(toJca(peer), true)
        generateSecret()
    }

    companion object {
        fun generate(): EphemeralKeyPair = EphemeralKeyPair(
            KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
        )

        private val p256Params: ECParameterSpec by lazy {
            AlgorithmParameters.getInstance("EC").apply { init(ECGenParameterSpec("secp256r1")) }
                .getParameterSpec(ECParameterSpec::class.java)
        }

        private fun toJca(key: EcPublicKey): ECPublicKey {
            val point = ECPoint(BigInteger(1, key.x), BigInteger(1, key.y))
            return KeyFactory.getInstance("EC").generatePublic(ECPublicKeySpec(point, p256Params)) as ECPublicKey
        }

        private fun fixed(b: BigInteger): ByteArray =
            b.toByteArray().dropWhile { it == 0.toByte() }.toByteArray().let { ByteArray(32 - it.size) + it }
    }
}

/**
 * mdoc session encryption (ISO/IEC 18013-5 §9.1.1): derives `SKDevice`/`SKReader` from the ECDH
 * secret and the SessionTranscript via HKDF-SHA256, then encrypts each message with AES-256-GCM.
 * The 12-byte IV is an 8-byte per-direction identifier (`…01` mdoc, `…00` reader) plus a 4-byte
 * big-endian message counter starting at 1.
 */
class SessionEncryption private constructor(
    private val sendKey: ByteArray,
    private val sendIdentifier: ByteArray,
    private val recvKey: ByteArray,
    private val recvIdentifier: ByteArray,
) {
    private var sendCounter = 0
    private var recvCounter = 0

    fun encrypt(plaintext: ByteArray): ByteArray {
        sendCounter++
        return gcm(sendKey, iv(sendIdentifier, sendCounter), plaintext, Cipher.ENCRYPT_MODE)
    }

    fun decrypt(ciphertext: ByteArray): ByteArray {
        recvCounter++
        return try {
            gcm(recvKey, iv(recvIdentifier, recvCounter), ciphertext, Cipher.DECRYPT_MODE)
        } catch (e: Exception) {
            throw ProximityException("session message authentication failed: ${e.message}")
        }
    }

    companion object {
        private val MDOC_IDENTIFIER = byteArrayOf(0, 0, 0, 0, 0, 0, 0, 1)
        private val READER_IDENTIFIER = byteArrayOf(0, 0, 0, 0, 0, 0, 0, 0)

        /** Wallet (mdoc) side: sends with SKDevice, receives reader messages with SKReader. */
        fun forMdoc(ephemeral: EphemeralKeyPair, readerPublicKey: EcPublicKey, sessionTranscriptBytes: ByteArray): SessionEncryption {
            val (skDevice, skReader) = deriveKeys(ephemeral.sharedSecret(readerPublicKey), sessionTranscriptBytes)
            return SessionEncryption(skDevice, MDOC_IDENTIFIER, skReader, READER_IDENTIFIER)
        }

        /** Reader side: sends with SKReader, receives mdoc messages with SKDevice. */
        fun forReader(ephemeral: EphemeralKeyPair, devicePublicKey: EcPublicKey, sessionTranscriptBytes: ByteArray): SessionEncryption {
            val (skDevice, skReader) = deriveKeys(ephemeral.sharedSecret(devicePublicKey), sessionTranscriptBytes)
            return SessionEncryption(skReader, READER_IDENTIFIER, skDevice, MDOC_IDENTIFIER)
        }

        private fun deriveKeys(sharedSecret: ByteArray, sessionTranscriptBytes: ByteArray): Pair<ByteArray, ByteArray> {
            val salt = MessageDigest.getInstance("SHA-256").digest(sessionTranscriptBytes)
            val skDevice = Hkdf.deriveSha256(sharedSecret, salt, "SKDevice".encodeToByteArray(), 32)
            val skReader = Hkdf.deriveSha256(sharedSecret, salt, "SKReader".encodeToByteArray(), 32)
            return skDevice to skReader
        }
    }

    private fun iv(identifier: ByteArray, counter: Int): ByteArray {
        val iv = identifier.copyOf(12)
        iv[8] = (counter ushr 24).toByte()
        iv[9] = (counter ushr 16).toByte()
        iv[10] = (counter ushr 8).toByte()
        iv[11] = counter.toByte()
        return iv
    }

    private fun gcm(key: ByteArray, iv: ByteArray, input: ByteArray, mode: Int): ByteArray =
        Cipher.getInstance("AES/GCM/NoPadding").apply {
            init(mode, SecretKeySpec(key, "AES"), GCMParameterSpec(128, iv))
        }.doFinal(input)
}
