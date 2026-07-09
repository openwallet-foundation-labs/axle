package com.hopae.eudi.wallet.proximity

import com.hopae.eudi.wallet.cbor.Cbor
import com.hopae.eudi.wallet.cbor.CborDecoder
import com.hopae.eudi.wallet.cbor.CborEncoder
import com.hopae.eudi.wallet.cbor.cose.CoseKey
import com.hopae.eudi.wallet.cbor.cose.EcPublicKey

/**
 * ISO/IEC 18013-5 device-retrieval message framing (§9.1.1):
 *  - `SessionEstablishment = {"eReaderKey": EReaderKeyBytes, "data": <encrypted DeviceRequest>}`
 *  - `SessionData = {"data": <encrypted DeviceResponse>, "status": uint?}`
 *
 * The encrypted `data` payloads are produced/consumed by [SessionEncryption]; this only wraps them.
 */
object SessionMessages {
    private const val TAG_ENCODED_CBOR = 24uL

    /** SessionData status codes (ISO 18013-5 Table 20). A status message must not also carry `data`. */
    object Status {
        const val SESSION_ENCRYPTION_ERROR = 10L
        const val CBOR_DECODING_ERROR = 11L
        const val SESSION_TERMINATION = 20L
    }

    fun encodeEstablishment(eReaderKey: EcPublicKey, encryptedDeviceRequest: ByteArray): ByteArray {
        val eReaderKeyBytes = Cbor.Tagged(TAG_ENCODED_CBOR, Cbor.Bytes(CborEncoder.encode(CoseKey.encode(eReaderKey))))
        return CborEncoder.encode(
            Cbor.CborMap(
                listOf(
                    Cbor.Text("eReaderKey") to eReaderKeyBytes,
                    Cbor.Text("data") to Cbor.Bytes(encryptedDeviceRequest),
                ),
            ),
        )
    }

    fun decodeEstablishment(bytes: ByteArray): SessionEstablishment {
        val map = CborDecoder.decode(bytes).asMap("SessionEstablishment")
        val tagged = map.field("eReaderKey") as? Cbor.Tagged ?: throw ProximityException("missing eReaderKey")
        val eReaderKey = CoseKey.decode(CborDecoder.decode((tagged.value as Cbor.Bytes).value).asMap("EReaderKey"))
        val data = (map.field("data") as? Cbor.Bytes)?.value ?: throw ProximityException("missing data")
        return SessionEstablishment(eReaderKey, data)
    }

    fun encodeData(encryptedDeviceResponse: ByteArray, status: Long? = null): ByteArray {
        val entries = buildList {
            add(Cbor.Text("data") to Cbor.Bytes(encryptedDeviceResponse))
            if (status != null) add(Cbor.Text("status") to Cbor.int(status))
        }
        return CborEncoder.encode(Cbor.CborMap(entries))
    }

    /** A `data`-less SessionData carrying only a status code — e.g. session termination (§9.1.1.4). */
    fun encodeStatus(status: Long): ByteArray =
        CborEncoder.encode(Cbor.CborMap(listOf(Cbor.Text("status") to Cbor.int(status))))

    /**
     * A decoded SessionData frame: the encrypted [data] (absent for a status-only message) and the
     * optional [status] code. Table 20 requires 10/11/20 to omit `data`; the receiver terminates on any.
     */
    class SessionData(val data: ByteArray?, val status: Long?)

    fun decodeSessionData(bytes: ByteArray): SessionData {
        val map = CborDecoder.decode(bytes).asMap("SessionData")
        val data = (map.field("data") as? Cbor.Bytes)?.value
        val status = (map.field("status"))?.let { (it as? Cbor.UInt)?.value?.toLong() }
        return SessionData(data, status)
    }

    /** The encrypted response payload, or an error when the frame is a bare status (no `data`). */
    fun decodeData(bytes: ByteArray): ByteArray =
        decodeSessionData(bytes).data ?: throw ProximityException("SessionData has no data")

    private fun Cbor.asMap(what: String): Cbor.CborMap =
        this as? Cbor.CborMap ?: throw ProximityException("$what must be a map")

    private fun Cbor.CborMap.field(key: String): Cbor? =
        entries.firstOrNull { (k, _) -> (k as? Cbor.Text)?.value == key }?.second
}

class SessionEstablishment(val eReaderKey: EcPublicKey, val encryptedDeviceRequest: ByteArray)
