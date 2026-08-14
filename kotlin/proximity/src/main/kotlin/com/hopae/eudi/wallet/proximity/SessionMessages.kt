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

    /**
     * `EReaderKeyBytes = #6.24(bstr .cbor EReaderKey)` (§9.1.1.4) for a key this party generated — the one
     * place the reader's ephemeral key is encoded, so the `SessionEstablishment` message and the
     * SessionTranscript are guaranteed to carry identical bytes (§8.1).
     */
    fun eReaderKeyBytes(eReaderKey: EcPublicKey): ByteArray =
        CborEncoder.encode(Cbor.Tagged(TAG_ENCODED_CBOR, Cbor.Bytes(CborEncoder.encode(CoseKey.encode(eReaderKey)))))

    fun encodeEstablishment(eReaderKey: EcPublicKey, encryptedDeviceRequest: ByteArray): ByteArray =
        encodeEstablishment(eReaderKeyBytes(eReaderKey), encryptedDeviceRequest)

    /** As above, from already-encoded `EReaderKeyBytes` — so a sender reuses the exact bytes it will bind. */
    fun encodeEstablishment(eReaderKeyBytes: ByteArray, encryptedDeviceRequest: ByteArray): ByteArray =
        CborEncoder.encode(
            Cbor.CborMap(
                listOf(
                    Cbor.Text("eReaderKey") to CborDecoder.decode(eReaderKeyBytes),
                    Cbor.Text("data") to Cbor.Bytes(encryptedDeviceRequest),
                ),
            ),
        )

    fun decodeEstablishment(bytes: ByteArray): SessionEstablishment {
        val map = CborDecoder.decode(bytes).asMap("SessionEstablishment")
        val tagged = map.field("eReaderKey") as? Cbor.Tagged ?: throw ProximityException("missing eReaderKey")
        if (tagged.tag != TAG_ENCODED_CBOR) throw ProximityException("eReaderKey must be #6.24")
        val inner = (tagged.value as? Cbor.Bytes)?.value ?: throw ProximityException("eReaderKey tag 24 value must be bstr")
        val eReaderKey = CoseKey.decode(CborDecoder.decode(inner).asMap("EReaderKey"))
        val data = (map.field("data") as? Cbor.Bytes)?.value ?: throw ProximityException("missing data")
        // Keep the received bytestring — the COSE_Key map inside is preserved verbatim, so a peer whose key
        // ordering or optional labels differ from ours still yields the same SessionTranscript (§8.1).
        return SessionEstablishment(eReaderKey, CborEncoder.encode(tagged), data)
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

/**
 * A decoded `SessionEstablishment` (§9.1.1.4). [eReaderKey] is the parsed key — use it for the ECDH;
 * [eReaderKeyBytes] is the `#6.24(bstr)` **as received** — use it for the SessionTranscript, which §8.1
 * forbids re-creating from the parsed map.
 */
class SessionEstablishment(
    val eReaderKey: EcPublicKey,
    val eReaderKeyBytes: ByteArray,
    val encryptedDeviceRequest: ByteArray,
)
