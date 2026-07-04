package com.hopae.eudi.wallet.cbor.cose

import java.math.BigInteger
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.PublicKey
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec

/**
 * ECDSA verification via JCA. Core rule: only public-key operations live in core —
 * private-key signing goes through the SecureArea port (see wallet-api).
 * Public because adapters need [publicKeyOf]/[parameterSpec] to build JCA peer keys.
 */
object Ecdsa {

    fun parameterSpec(curve: EcCurve): ECParameterSpec =
        AlgorithmParameters.getInstance("EC").run {
            init(ECGenParameterSpec(curve.jcaName))
            getParameterSpec(ECParameterSpec::class.java)
        }

    fun publicKeyOf(key: EcPublicKey): PublicKey {
        val point = ECPoint(BigInteger(1, key.x), BigInteger(1, key.y))
        return KeyFactory.getInstance("EC")
            .generatePublic(ECPublicKeySpec(point, parameterSpec(key.curve)))
    }

    /** Verifies a raw (r||s) COSE signature. Returns false on any structural mismatch. */
    fun verify(key: EcPublicKey, algorithm: CoseAlgorithm, data: ByteArray, rawSignature: ByteArray): Boolean {
        if (rawSignature.size != 2 * key.curve.coordinateSize) return false
        return runCatching {
            Signature.getInstance(algorithm.jcaName).run {
                initVerify(publicKeyOf(key))
                update(data)
                verify(Der.rawSignatureToDer(rawSignature))
            }
        }.getOrDefault(false)
    }
}

/**
 * Minimal DER helpers for ECDSA signature conversion (COSE raw r||s <-> DER).
 * Public because platform keystores (Android Keystore, JCA) emit DER signatures.
 */
object Der {

    fun rawSignatureToDer(raw: ByteArray): ByteArray {
        require(raw.size % 2 == 0) { "raw signature must be r||s" }
        val half = raw.size / 2
        val body = integer(raw.copyOfRange(0, half)) + integer(raw.copyOfRange(half, raw.size))
        return byteArrayOf(0x30) + length(body.size) + body
    }

    fun derSignatureToRaw(der: ByteArray, coordinateSize: Int): ByteArray {
        var pos = 0
        fun byte(): Int {
            require(pos < der.size) { "truncated DER" }
            return der[pos++].toInt() and 0xFF
        }
        fun len(): Int {
            val first = byte()
            if (first < 0x80) return first
            require(first == 0x81) { "unsupported DER length" }
            return byte()
        }
        require(byte() == 0x30) { "not a DER sequence" }
        len()
        fun integer(): ByteArray {
            require(byte() == 0x02) { "expected DER integer" }
            val n = len()
            val bytes = der.copyOfRange(pos, pos + n)
            pos += n
            val stripped = bytes.dropWhile { it == 0.toByte() }.toByteArray()
            require(stripped.size <= coordinateSize) { "integer larger than curve size" }
            return ByteArray(coordinateSize - stripped.size) + stripped
        }
        val r = integer()
        val s = integer()
        return r + s
    }

    private fun integer(magnitude: ByteArray): ByteArray {
        var b = magnitude.dropWhile { it == 0.toByte() }.toByteArray()
        if (b.isEmpty()) b = byteArrayOf(0)
        if (b[0].toInt() < 0) b = byteArrayOf(0) + b
        return byteArrayOf(0x02) + length(b.size) + b
    }

    private fun length(n: Int): ByteArray =
        if (n < 0x80) byteArrayOf(n.toByte()) else byteArrayOf(0x81.toByte(), n.toByte())
}
