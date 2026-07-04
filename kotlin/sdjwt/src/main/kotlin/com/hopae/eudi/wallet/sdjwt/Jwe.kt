package com.hopae.eudi.wallet.sdjwt

import com.hopae.eudi.wallet.cbor.cose.EcCurve
import com.hopae.eudi.wallet.cbor.cose.EcPublicKey
import com.hopae.eudi.wallet.cbor.cose.Ecdsa
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

class JweException(message: String) : Exception(message)

/** JWE content-encryption algorithms this SDK supports (AES-GCM, RFC 7518 §5.3). */
enum class JweEnc(val id: String, val keyBits: Int) {
    A128GCM("A128GCM", 128),
    A192GCM("A192GCM", 192),
    A256GCM("A256GCM", 256);

    companion object {
        fun from(id: String): JweEnc? = entries.firstOrNull { it.id == id }
    }
}

/**
 * JWE with ECDH-ES direct key agreement (RFC 7518 §4.6) + AES-GCM.
 *
 * This is the OpenID4VP `direct_post.jwt` response-encryption path: the wallet encrypts to the
 * verifier's public key. Only ECDH-ES (direct, empty encrypted_key) is implemented — the
 * key-wrapping variants (ECDH-ES+A128KW…) and RSA are out of scope for HAIP.
 */
object Jwe {

    /** Encrypts [plaintext] to [recipient] (ECDH-ES direct). Returns compact JWE. */
    fun encryptEcdhEs(
        plaintext: ByteArray,
        recipient: EcPublicKey,
        enc: JweEnc = JweEnc.A128GCM,
        apu: ByteArray? = null,
        apv: ByteArray? = null,
    ): String {
        // ephemeral EC key on the recipient's curve
        val kpg = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec(recipient.curve.jcaName)) }
        val ephemeral = kpg.generateKeyPair()
        val ephPub = ephemeral.public as ECPublicKey

        val z = KeyAgreement.getInstance("ECDH").run {
            init(ephemeral.private)
            doPhase(Ecdsa.publicKeyOf(recipient), true)
            generateSecret()
        }
        val cek = concatKdf(z, enc.keyBits, enc.id, apu ?: ByteArray(0), apv ?: ByteArray(0))

        val header = JsonValue.Obj(
            buildList {
                add("alg" to JsonValue.Str("ECDH-ES"))
                add("enc" to JsonValue.Str(enc.id))
                add("epk" to ephemeralJwk(recipient.curve, ephPub))
                apu?.let { add("apu" to JsonValue.Str(Base64Url.encode(it))) }
                apv?.let { add("apv" to JsonValue.Str(Base64Url.encode(it))) }
            }
        )
        val headerB64 = Base64Url.encode(header.serialize())
        val aad = headerB64.encodeToByteArray()

        val iv = ByteArray(12).also { java.security.SecureRandom().nextBytes(it) }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding").apply {
            init(Cipher.ENCRYPT_MODE, SecretKeySpec(cek, "AES"), GCMParameterSpec(128, iv))
            updateAAD(aad)
        }
        val out = cipher.doFinal(plaintext)
        val ciphertext = out.copyOfRange(0, out.size - 16)
        val tag = out.copyOfRange(out.size - 16, out.size)

        return listOf(headerB64, "", Base64Url.encode(iv), Base64Url.encode(ciphertext), Base64Url.encode(tag))
            .joinToString(".")
    }

    /**
     * Decrypts a compact ECDH-ES JWE with the recipient private key material (raw scalar `d`
     * and curve). Verifier-side — used by tests and any verifier the SDK powers.
     */
    fun decryptEcdhEs(compact: String, recipientPrivateD: ByteArray, curve: EcCurve): ByteArray {
        val parts = compact.split('.')
        if (parts.size != 5) throw JweException("compact JWE must have 5 parts")
        val header = JsonValue.parse(Base64Url.decodeToString(parts[0])) as? JsonValue.Obj
            ?: throw JweException("JWE header must be an object")
        if ((header["alg"] as? JsonValue.Str)?.value != "ECDH-ES") throw JweException("unsupported alg")
        val enc = JweEnc.from((header["enc"] as? JsonValue.Str)?.value ?: "")
            ?: throw JweException("unsupported enc")
        val epk = JwkEc.fromJson(header["epk"] as? JsonValue.Obj ?: throw JweException("missing epk"))
            ?: throw JweException("bad epk")
        val apu = (header["apu"] as? JsonValue.Str)?.value?.let { Base64Url.decode(it) } ?: ByteArray(0)
        val apv = (header["apv"] as? JsonValue.Str)?.value?.let { Base64Url.decode(it) } ?: ByteArray(0)

        val privateKey = java.security.KeyFactory.getInstance("EC").generatePrivate(
            java.security.spec.ECPrivateKeySpec(java.math.BigInteger(1, recipientPrivateD), Ecdsa.parameterSpec(curve))
        )
        val z = KeyAgreement.getInstance("ECDH").run {
            init(privateKey)
            doPhase(Ecdsa.publicKeyOf(epk), true)
            generateSecret()
        }
        val cek = concatKdf(z, enc.keyBits, enc.id, apu, apv)

        val iv = Base64Url.decode(parts[2])
        val ciphertext = Base64Url.decode(parts[3])
        val tag = Base64Url.decode(parts[4])
        val cipher = Cipher.getInstance("AES/GCM/NoPadding").apply {
            init(Cipher.DECRYPT_MODE, SecretKeySpec(cek, "AES"), GCMParameterSpec(128, iv))
            updateAAD(parts[0].encodeToByteArray())
        }
        return cipher.doFinal(ciphertext + tag)
    }

    private fun ephemeralJwk(curve: EcCurve, pub: ECPublicKey): JsonValue.Obj {
        val size = curve.coordinateSize
        fun fixed(b: java.math.BigInteger): ByteArray {
            val s = b.toByteArray().dropWhile { it == 0.toByte() }.toByteArray()
            return ByteArray(size - s.size) + s
        }
        return JwkEc.toJson(EcPublicKey(curve, fixed(pub.w.affineX), fixed(pub.w.affineY)))
    }

    /**
     * Concat KDF (NIST SP 800-56A single-step KDF) for ECDH-ES direct (RFC 7518 §4.6.2).
     * AlgorithmID = the `enc` value; SuppPubInfo = keydatalen; apu/apv are length-prefixed.
     */
    internal fun concatKdf(z: ByteArray, keyBits: Int, algId: String, apu: ByteArray, apv: ByteArray): ByteArray {
        val keyBytes = keyBits / 8
        val sha = MessageDigest.getInstance("SHA-256")
        val hashLen = 32
        val reps = (keyBytes + hashLen - 1) / hashLen

        val otherInfo = lengthPrefixed(algId.encodeToByteArray()) +
            lengthPrefixed(apu) +
            lengthPrefixed(apv) +
            uint32(keyBits)

        val out = java.io.ByteArrayOutputStream()
        for (i in 1..reps) {
            sha.reset()
            sha.update(uint32(i))
            sha.update(z)
            sha.update(otherInfo)
            out.write(sha.digest())
        }
        return out.toByteArray().copyOfRange(0, keyBytes)
    }

    private fun lengthPrefixed(data: ByteArray): ByteArray = uint32(data.size) + data

    private fun uint32(v: Int): ByteArray =
        byteArrayOf((v ushr 24).toByte(), (v ushr 16).toByte(), (v ushr 8).toByte(), v.toByte())
}
