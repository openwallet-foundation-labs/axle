package com.hopae.eudi.wallet.proximity

/** A parsed ISO 18013-5 NFC static handover: the DeviceEngagement + the BLE carrier (service UUID, mode). */
class NfcEngagement(val deviceEngagement: ByteArray, val serviceUuid: ByteArray, val peripheralServerMode: Boolean)

/**
 * ISO/IEC 18013-5 §8.3.3.1.2 NFC **static handover** — the mdoc serves a Handover Select NDEF message
 * (`Hs` record + a `DeviceEngagement` record + a BLE carrier-configuration record). The reader reads it,
 * extracts the engagement + BLE service UUID, and the connection continues over BLE. The full Handover
 * Select message is bound into the SessionTranscript via [ProximitySessionTranscript.nfcHandover].
 */
object MdocNfcEngagement {
    private const val HANDOVER_VERSION = 0x15 // Connection Handover 1.5
    private val OOB_MIME = "application/vnd.bluetooth.le.oob".toByteArray()
    private val DE_TYPE = "iso.org:18013:deviceengagement".toByteArray()
    private const val AD_LE_ROLE = 0x1C
    private const val AD_UUID128 = 0x07

    /** Builds the static Handover Select NDEF message. [serviceUuid] is the 16-byte big-endian BLE service UUID. */
    fun buildHandoverSelect(deviceEngagement: ByteArray, serviceUuid: ByteArray, peripheralServerMode: Boolean = true): ByteArray {
        // Alternative Carrier record (embedded in the Hs record): points at BLE carrier "0" + aux "mdoc".
        val ac = NdefRecord(
            Ndef.TNF_WELL_KNOWN, "ac".toByteArray(),
            payload = byteArrayOf(0x01, 0x01, '0'.code.toByte(), 0x01, 0x04, 'm'.code.toByte(), 'd'.code.toByte(), 'o'.code.toByte(), 'c'.code.toByte()),
        )
        val hs = NdefRecord(
            Ndef.TNF_WELL_KNOWN, "Hs".toByteArray(),
            payload = byteArrayOf(HANDOVER_VERSION.toByte()) + Ndef.encodeMessage(listOf(ac)),
        )
        val de = NdefRecord(Ndef.TNF_EXTERNAL, DE_TYPE, "mdoc".toByteArray(), deviceEngagement)

        // BLE carrier config: LE Role (reader's role — central when the mdoc is the peripheral server) + the
        // 128-bit service UUID, written little-endian (the reverse of the canonical big-endian bytes).
        val leRole = if (peripheralServerMode) 0x00 else 0x01
        val oobPayload = byteArrayOf(0x02, AD_LE_ROLE.toByte(), leRole.toByte(), 0x11, AD_UUID128.toByte()) + serviceUuid.reversedArray()
        val oob = NdefRecord(Ndef.TNF_MIME_MEDIA, OOB_MIME, "0".toByteArray(), oobPayload)

        return Ndef.encodeMessage(listOf(hs, de, oob))
    }

    /** Parses a static Handover Select NDEF message → the DeviceEngagement, BLE service UUID (big-endian), and mode. */
    fun parseHandoverSelect(ndef: ByteArray): NfcEngagement? {
        val records = runCatching { Ndef.decodeMessage(ndef) }.getOrNull() ?: return null
        val hs = records.firstOrNull { it.tnf == Ndef.TNF_WELL_KNOWN && it.type.contentEquals("Hs".toByteArray()) } ?: return null
        if (hs.payload.isEmpty() || hs.payload[0].toInt() != HANDOVER_VERSION) return null
        val de = records.firstOrNull { it.tnf == Ndef.TNF_EXTERNAL && it.type.contentEquals(DE_TYPE) }?.payload ?: return null
        val oob = records.firstOrNull { it.tnf == Ndef.TNF_MIME_MEDIA && it.type.contentEquals(OOB_MIME) } ?: return null

        var i = 0
        var leRole = 0
        var uuid: ByteArray? = null
        val p = oob.payload
        while (i < p.size) {
            val len = p[i].toInt() and 0xFF
            if (len == 0 || i + 1 + len > p.size) break
            val data = p.copyOfRange(i + 2, i + 1 + len)
            when (p[i + 1].toInt() and 0xFF) {
                AD_LE_ROLE -> if (data.isNotEmpty()) leRole = data[0].toInt() and 0xFF
                AD_UUID128 -> if (data.size == 16) uuid = data.reversedArray() // little-endian → canonical big-endian
            }
            i += 1 + len
        }
        val serviceUuid = uuid ?: return null
        return NfcEngagement(de, serviceUuid, peripheralServerMode = leRole == 0x00)
    }
}
