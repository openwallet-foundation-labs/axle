package com.hopae.eudi.wallet.cbor.cose

import com.hopae.eudi.wallet.cbor.Cbor
import com.hopae.eudi.wallet.cbor.CborDecoder
import com.hopae.eudi.wallet.cbor.CborEncoder

class CoseException(message: String) : Exception(message)

/** COSE signature algorithms (RFC 9053 §2.1). */
enum class CoseAlgorithm(val label: Long, val jcaName: String) {
    ES256(-7, "SHA256withECDSA"),
    ES384(-35, "SHA384withECDSA"),
    ES512(-36, "SHA512withECDSA");

    companion object {
        fun fromLabel(label: Long): CoseAlgorithm? = entries.firstOrNull { it.label == label }
    }
}

private fun Cbor.asLongOrNull(): Long? = when (this) {
    is Cbor.UInt -> if (value <= Long.MAX_VALUE.toULong()) value.toLong() else null
    is Cbor.NInt -> if (n < Long.MAX_VALUE.toULong()) -1L - n.toLong() else null
    else -> null
}

/** COSE header map (RFC 9052 §3) with typed accessors for the labels the wallet uses. */
class CoseHeaders(val map: Cbor.CborMap) {

    constructor(vararg entries: Pair<Cbor, Cbor>) : this(Cbor.CborMap(entries.toList()))

    val isEmpty: Boolean get() = map.entries.isEmpty()

    private fun value(label: Long): Cbor? =
        map.entries.firstOrNull { (k, _) -> k.asLongOrNull() == label }?.second

    val algorithm: CoseAlgorithm?
        get() = value(LABEL_ALG)?.asLongOrNull()?.let { CoseAlgorithm.fromLabel(it) }

    val kid: ByteArray? get() = (value(LABEL_KID) as? Cbor.Bytes)?.value

    /** x5chain (RFC 9360, label 33): single bstr or array of bstr, leaf first. */
    val x5chain: List<ByteArray>?
        get() = when (val v = value(LABEL_X5CHAIN)) {
            null -> null
            is Cbor.Bytes -> listOf(v.value)
            is Cbor.Array -> v.items.map {
                (it as? Cbor.Bytes)?.value ?: throw CoseException("x5chain items must be bstr")
            }
            else -> throw CoseException("x5chain must be bstr or array of bstr")
        }

    companion object {
        const val LABEL_ALG = 1L
        const val LABEL_KID = 4L
        const val LABEL_X5CHAIN = 33L

        fun of(algorithm: CoseAlgorithm? = null, kid: ByteArray? = null): CoseHeaders {
            val entries = buildList {
                algorithm?.let { add(Cbor.int(LABEL_ALG) to Cbor.int(it.label)) }
                kid?.let { add(Cbor.int(LABEL_KID) to Cbor.Bytes(it)) }
            }
            return CoseHeaders(Cbor.CborMap(entries))
        }

        /** Decodes serialized protected headers; empty bstr means empty map. */
        fun decode(protectedBytes: ByteArray): CoseHeaders {
            if (protectedBytes.isEmpty()) return CoseHeaders(Cbor.CborMap(emptyList()))
            val c = CborDecoder.decode(protectedBytes)
            return CoseHeaders(c as? Cbor.CborMap ?: throw CoseException("protected headers must be a map"))
        }
    }
}

/** The signer abstraction the SecureArea adapter will implement (raw r||s signatures). */
interface CoseSigner {
    val algorithm: CoseAlgorithm
    suspend fun sign(toBeSigned: ByteArray): ByteArray
}

/**
 * COSE_Sign1 (RFC 9052 §4.2). [protectedBytes] preserves the exact wire bytes so
 * verification is byte-faithful even for non-canonical peers.
 */
class CoseSign1(
    val protectedBytes: ByteArray,
    val unprotected: CoseHeaders,
    val payload: ByteArray?,
    val signature: ByteArray,
) {
    val protected: CoseHeaders by lazy { CoseHeaders.decode(protectedBytes) }

    /** alg resolution: protected first (mdoc puts it there), unprotected as fallback. */
    val algorithm: CoseAlgorithm? get() = protected.algorithm ?: unprotected.algorithm

    fun toCbor(tagged: Boolean = true): Cbor {
        val arr = Cbor.Array(
            listOf(
                Cbor.Bytes(protectedBytes),
                unprotected.map,
                payload?.let { Cbor.Bytes(it) } ?: Cbor.Null,
                Cbor.Bytes(signature),
            )
        )
        return if (tagged) Cbor.Tagged(TAG, arr) else arr
    }

    fun encode(tagged: Boolean = true): ByteArray = CborEncoder.encode(toCbor(tagged))

    fun verify(
        publicKey: EcPublicKey,
        externalAad: ByteArray = ByteArray(0),
        detachedPayload: ByteArray? = null,
    ): Boolean {
        val alg = algorithm ?: return false
        val p = payload ?: detachedPayload ?: return false
        return Ecdsa.verify(publicKey, alg, sigStructure(protectedBytes, externalAad, p), signature)
    }

    companion object {
        val TAG: ULong = 18u
        private val EMPTY_MAP = byteArrayOf(0xA0.toByte())

        fun decode(bytes: ByteArray, strict: Boolean = true): CoseSign1 =
            fromCbor(CborDecoder.decode(bytes, strict))

        fun fromCbor(c: Cbor): CoseSign1 {
            val body = when (c) {
                is Cbor.Tagged -> {
                    if (c.tag != TAG) throw CoseException("unexpected tag ${c.tag} for COSE_Sign1")
                    c.value
                }
                else -> c
            }
            val arr = body as? Cbor.Array ?: throw CoseException("COSE_Sign1 must be an array")
            if (arr.items.size != 4) throw CoseException("COSE_Sign1 must have 4 elements")
            val prot = (arr.items[0] as? Cbor.Bytes)?.value ?: throw CoseException("protected must be bstr")
            val unp = arr.items[1] as? Cbor.CborMap ?: throw CoseException("unprotected must be a map")
            val payload = when (val p = arr.items[2]) {
                is Cbor.Bytes -> p.value
                Cbor.Null -> null
                else -> throw CoseException("payload must be bstr or null")
            }
            val sig = (arr.items[3] as? Cbor.Bytes)?.value ?: throw CoseException("signature must be bstr")
            return CoseSign1(prot, CoseHeaders(unp), payload, sig)
        }

        /**
         * Sig_structure (RFC 9052 §4.4). An empty protected map — whether encoded as
         * h'' or h'A0' on the wire — normalizes to a zero-length bstr (cose-wg sign-pass-01).
         */
        fun sigStructure(protectedBytes: ByteArray, externalAad: ByteArray, payload: ByteArray): ByteArray {
            val normalized =
                if (protectedBytes.isEmpty() || protectedBytes.contentEquals(EMPTY_MAP)) ByteArray(0)
                else protectedBytes
            return CborEncoder.encode(
                Cbor.Array(
                    listOf(
                        Cbor.Text("Signature1"),
                        Cbor.Bytes(normalized),
                        Cbor.Bytes(externalAad),
                        Cbor.Bytes(payload),
                    )
                )
            )
        }

        suspend fun sign(
            protected: CoseHeaders,
            unprotected: CoseHeaders = CoseHeaders(),
            payload: ByteArray?,
            externalAad: ByteArray = ByteArray(0),
            detachedPayload: ByteArray? = null,
            signer: CoseSigner,
        ): CoseSign1 {
            val protBytes = if (protected.isEmpty) ByteArray(0) else CborEncoder.encode(protected.map)
            val p = payload ?: detachedPayload ?: throw CoseException("payload required (embedded or detached)")
            val sig = signer.sign(sigStructure(protBytes, externalAad, p))
            return CoseSign1(protBytes, unprotected, payload, sig)
        }
    }
}
