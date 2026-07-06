package com.hopae.eudi.wallet.cbor.cose

import com.hopae.eudi.wallet.cbor.Cbor
import com.hopae.eudi.wallet.cbor.CborEncoder
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * COSE_Mac0 (RFC 9052 §6.2) with HMAC 256/256 — the MAC form of mdoc device authentication
 * (ISO/IEC 18013-5 §9.1.3.5, `deviceMac`). Verified with the `EMacKey` derived from the EReaderKey /
 * DeviceKey ECDH secret; the counterpart of [CoseSign1] for key-agreement device keys.
 */
class CoseMac0(
    val protectedBytes: ByteArray,
    val unprotected: CoseHeaders,
    val payload: ByteArray?,
    val tag: ByteArray,
) {
    /** Verifies the HMAC-SHA256 tag over the MAC_structure with [key] (EMacKey), using [detachedPayload] if detached. */
    fun verify(key: ByteArray, externalAad: ByteArray = ByteArray(0), detachedPayload: ByteArray? = null): Boolean {
        val p = payload ?: detachedPayload ?: return false
        val expected = hmacSha256(key, macStructure(protectedBytes, externalAad, p))
        return expected.contentEquals(tag)
    }

    companion object {
        val TAG: ULong = 17u
        private val EMPTY_MAP = byteArrayOf(0xA0.toByte())

        fun fromCbor(c: Cbor): CoseMac0 {
            val body = when (c) {
                is Cbor.Tagged -> {
                    if (c.tag != TAG) throw CoseException("unexpected tag ${c.tag} for COSE_Mac0")
                    c.value
                }
                else -> c
            }
            val arr = body as? Cbor.Array ?: throw CoseException("COSE_Mac0 must be an array")
            if (arr.items.size != 4) throw CoseException("COSE_Mac0 must have 4 elements")
            val prot = (arr.items[0] as? Cbor.Bytes)?.value ?: throw CoseException("protected must be bstr")
            val unp = arr.items[1] as? Cbor.CborMap ?: throw CoseException("unprotected must be a map")
            val payload = when (val pl = arr.items[2]) {
                is Cbor.Bytes -> pl.value
                Cbor.Null -> null
                else -> throw CoseException("payload must be bstr or null")
            }
            val tag = (arr.items[3] as? Cbor.Bytes)?.value ?: throw CoseException("tag must be bstr")
            return CoseMac0(prot, CoseHeaders(unp), payload, tag)
        }

        /** MAC_structure (RFC 9052 §6.3), context "MAC0". An empty protected map normalizes to a zero-length bstr. */
        private fun macStructure(protectedBytes: ByteArray, externalAad: ByteArray, payload: ByteArray): ByteArray {
            val normalized =
                if (protectedBytes.isEmpty() || protectedBytes.contentEquals(EMPTY_MAP)) ByteArray(0) else protectedBytes
            return CborEncoder.encode(
                Cbor.Array(
                    listOf(Cbor.Text("MAC0"), Cbor.Bytes(normalized), Cbor.Bytes(externalAad), Cbor.Bytes(payload)),
                ),
            )
        }

        private fun hmacSha256(key: ByteArray, data: ByteArray): ByteArray =
            Mac.getInstance("HmacSHA256").apply { init(SecretKeySpec(key, "HmacSHA256")) }.doFinal(data)
    }
}
