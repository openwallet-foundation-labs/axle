package com.hopae.eudi.wallet.proximity

/** A parsed ISO 18013-5 NFC static handover: the DeviceEngagement + the BLE carrier (service UUID, mode). */
class NfcEngagement(val deviceEngagement: ByteArray, val serviceUuid: ByteArray, val peripheralServerMode: Boolean)

/**
 * A parsed ISO 18013-5 NFC negotiated Handover Request: the reader's BLE carrier + optional ReaderEngagement.
 *
 * [peripheralServerMode] is the carrier record's LE Role read from its **sender**, the mdoc reader — true means
 * *the reader* is the BLE peripheral, which per §8.3.3.1.1.2 is the reader offering **mdoc central client mode**.
 * It is not the mdoc's mode; on a Handover Select ([NfcEngagement.peripheralServerMode]) the same flag does mean
 * the mdoc's mode, because there the mdoc is the sender.
 */
class NfcHandoverRequest(val serviceUuid: ByteArray, val peripheralServerMode: Boolean, val readerEngagement: ByteArray?)

/**
 * ISO/IEC 18013-5 §8.2.2.1 / §8.3.3.1.2 NFC handover.
 *
 * **Static handover** — the mdoc serves a Handover Select NDEF message (`Hs` record + a `DeviceEngagement`
 * record + a BLE carrier-configuration record). The reader reads it, extracts the engagement + BLE service
 * UUID, and the connection continues over BLE.
 *
 * **Negotiated handover** — the mdoc reader (Handover Requester) sends a Handover Request NDEF message
 * (`Hr` record + a collision-resolution record + the reader's carrier(s), optionally a `ReaderEngagement`
 * aux record); the mdoc confirms with a Handover Select carrying exactly one selected carrier. Both the
 * Handover Select **and** the Handover Request are bound into the SessionTranscript via
 * [ProximitySessionTranscript.nfcHandover]; static handover binds only the Select (request = null).
 */
object MdocNfcEngagement {
    private const val HANDOVER_VERSION = 0x15 // Connection Handover 1.5
    private val OOB_MIME = "application/vnd.bluetooth.le.oob".toByteArray()
    private val DE_TYPE = "iso.org:18013:deviceengagement".toByteArray()
    private val RE_TYPE = "iso.org:18013:readerengagement".toByteArray()
    private const val AD_LE_ROLE = 0x1C
    private const val AD_UUID128 = 0x07

    /** Builds the static Handover Select NDEF message. [serviceUuid] is the 16-byte big-endian BLE service UUID. */
    fun buildHandoverSelect(deviceEngagement: ByteArray, serviceUuid: ByteArray, peripheralServerMode: Boolean = true): ByteArray {
        val hs = NdefRecord(
            Ndef.TNF_WELL_KNOWN, "Hs".toByteArray(),
            payload = byteArrayOf(HANDOVER_VERSION.toByte()) + Ndef.encodeMessage(listOf(acRecord("mdoc"))),
        )
        val de = NdefRecord(Ndef.TNF_EXTERNAL, DE_TYPE, "mdoc".toByteArray(), deviceEngagement)
        return Ndef.encodeMessage(listOf(hs, de, bleOobRecord(serviceUuid, peripheralServerMode)))
    }

    /** Parses a static Handover Select NDEF message → the DeviceEngagement, BLE service UUID (big-endian), and mode. */
    fun parseHandoverSelect(ndef: ByteArray): NfcEngagement? {
        val records = runCatching { Ndef.decodeMessage(ndef) }.getOrNull() ?: return null
        if (!hasHandover(records, "Hs")) return null
        val de = records.firstOrNull { it.tnf == Ndef.TNF_EXTERNAL && it.type.contentEquals(DE_TYPE) }?.payload ?: return null
        val (uuid, peripheralServerMode) = parseOob(records) ?: return null
        return NfcEngagement(de, uuid, peripheralServerMode)
    }

    /**
     * Resolves the carrier of a finished handover, which the Handover Select alone does not always name.
     * §8.3.3.1.1.2 splits where the UUID lives: the mdoc puts one in its **Select** when it picks mdoc
     * peripheral server mode, whereas the UUID for **mdoc central client mode** is the one the reader offered in
     * its **Request** — a Select accepting that carrier names no UUID of its own, so only the pair identifies the
     * connection. Prefer this over [parseHandoverSelect] on the reader side; pass [handoverRequest] = null for
     * static handover, where there is no Request and the Select must be self-contained.
     */
    fun parseHandover(handoverSelect: ByteArray, handoverRequest: ByteArray? = null): NfcEngagement? {
        parseHandoverSelect(handoverSelect)?.let { return it }
        // No carrier of the mdoc's own → it took ours, whose LE Role (the *reader's* role) says which mode that is:
        // reader-as-peripheral is mdoc central client mode; reader-as-central would have needed the mdoc's UUID.
        val request = handoverRequest?.let { parseHandoverRequest(it) }?.takeIf { it.peripheralServerMode } ?: return null
        val records = runCatching { Ndef.decodeMessage(handoverSelect) }.getOrNull() ?: return null
        if (!hasHandover(records, "Hs")) return null
        val de = records.firstOrNull { it.tnf == Ndef.TNF_EXTERNAL && it.type.contentEquals(DE_TYPE) }?.payload ?: return null
        return NfcEngagement(de, request.serviceUuid, peripheralServerMode = false)
    }

    /**
     * Builds the negotiated-handover Handover Request NDEF message the mdoc **reader** sends to the mdoc
     * (§8.2.2.1): an `Hr` record (version + collision-resolution record + one Alternative Carrier) plus the
     * BLE carrier-configuration record, and optionally a `ReaderEngagement` auxiliary record.
     * [collisionResolution] is the 2-byte random the reader picks (NFC Forum CH); [serviceUuid] is the
     * 16-byte big-endian BLE service UUID.
     *
     * **[peripheralServerMode] means the opposite thing here than in [buildHandoverSelect].** The LE Role in a
     * carrier-configuration record describes the *sender's* role, and §8.3.3.1.1.2 pins each message's meaning:
     * a UUID in the Handover **Request** is "the mdoc reader supports **mdoc central client mode**", a UUID in
     * the Handover **Select** is "the mdoc chooses **mdoc peripheral server mode**". So on this (reader) side
     * `true` emits LE Role = Peripheral, i.e. *the reader* is the peripheral / GATT server and the mdoc is the
     * central client — the mdoc-mode reading of the flag is inverted. [parseHandoverRequest] returns the same
     * sender-relative value. Pass `true` unless the reader intends to be the BLE central.
     */
    fun buildHandoverRequest(
        serviceUuid: ByteArray,
        collisionResolution: ByteArray,
        peripheralServerMode: Boolean = true,
        readerEngagement: ByteArray? = null,
    ): ByteArray {
        val cr = NdefRecord(Ndef.TNF_WELL_KNOWN, "cr".toByteArray(), payload = collisionResolution)
        val hr = NdefRecord(
            Ndef.TNF_WELL_KNOWN, "Hr".toByteArray(),
            payload = byteArrayOf(HANDOVER_VERSION.toByte()) +
                Ndef.encodeMessage(listOf(cr, acRecord(readerEngagement?.let { "mdocreader" }))),
        )
        val records = mutableListOf(hr)
        readerEngagement?.let { records.add(NdefRecord(Ndef.TNF_EXTERNAL, RE_TYPE, "mdocreader".toByteArray(), it)) }
        records.add(bleOobRecord(serviceUuid, peripheralServerMode))
        return Ndef.encodeMessage(records)
    }

    /** Parses a negotiated Handover Request NDEF message → the reader's BLE carrier and optional ReaderEngagement. */
    fun parseHandoverRequest(ndef: ByteArray): NfcHandoverRequest? {
        val records = runCatching { Ndef.decodeMessage(ndef) }.getOrNull() ?: return null
        if (!hasHandover(records, "Hr")) return null
        val (uuid, peripheralServerMode) = parseOob(records) ?: return null
        val re = records.firstOrNull { it.tnf == Ndef.TNF_EXTERNAL && it.type.contentEquals(RE_TYPE) }?.payload
        return NfcHandoverRequest(uuid, peripheralServerMode, re)
    }

    /** Minimal ReaderEngagement (§8.2.2.1): `{0: version}` — a reader-supplied structure carried as Hr aux data. */
    fun readerEngagement(version: String = "1.0"): ByteArray =
        com.hopae.eudi.wallet.cbor.CborEncoder.encode(
            com.hopae.eudi.wallet.cbor.Cbor.CborMap(
                listOf(com.hopae.eudi.wallet.cbor.Cbor.int(0) to com.hopae.eudi.wallet.cbor.Cbor.Text(version)),
            ),
        )

    /** True when the message opens with a Handover record ([kind] = "Hs" or "Hr") of the supported CH version. */
    private fun hasHandover(records: List<NdefRecord>, kind: String): Boolean {
        val h = records.firstOrNull { it.tnf == Ndef.TNF_WELL_KNOWN && it.type.contentEquals(kind.toByteArray()) } ?: return false
        return h.payload.isNotEmpty() && h.payload[0].toInt() == HANDOVER_VERSION
    }

    /** An Alternative Carrier record: active carrier, data reference "0", optional single aux-data reference. */
    private fun acRecord(auxRef: String?): NdefRecord {
        val head = byteArrayOf(0x01, 0x01, '0'.code.toByte()) // CPS=active, carrier-data-ref "0"
        val aux = auxRef?.let { byteArrayOf(0x01, it.length.toByte()) + it.toByteArray() } ?: byteArrayOf(0x00)
        return NdefRecord(Ndef.TNF_WELL_KNOWN, "ac".toByteArray(), payload = head + aux)
    }

    /** BLE carrier-config record (id "0"): LE Role + the 128-bit service UUID written little-endian. */
    private fun bleOobRecord(serviceUuid: ByteArray, peripheralServerMode: Boolean): NdefRecord {
        val leRole = if (peripheralServerMode) 0x00 else 0x01
        val oobPayload = byteArrayOf(0x02, AD_LE_ROLE.toByte(), leRole.toByte(), 0x11, AD_UUID128.toByte()) + serviceUuid.reversedArray()
        return NdefRecord(Ndef.TNF_MIME_MEDIA, OOB_MIME, "0".toByteArray(), oobPayload)
    }

    /** Reads the BLE service UUID (returned big-endian) and mode from the OOB carrier-config record. */
    private fun parseOob(records: List<NdefRecord>): Pair<ByteArray, Boolean>? {
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
        return (uuid ?: return null) to (leRole == 0x00)
    }
}
