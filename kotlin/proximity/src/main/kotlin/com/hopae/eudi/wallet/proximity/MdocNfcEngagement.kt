package com.hopae.eudi.wallet.proximity

/** A parsed ISO 18013-5 NFC static handover: the DeviceEngagement + the BLE carrier (service UUID, mode). */
class NfcEngagement(val deviceEngagement: ByteArray, val serviceUuid: ByteArray, val peripheralServerMode: Boolean)

/**
 * One BLE carrier-configuration record of an NFC handover message: the service UUID it names (big-endian, null
 * when the record carries none) and the raw Bluetooth CSS **LE Role** (0x1C) value.
 *
 * LE Role always describes the record's **sender**, and it has four defined values — the two "supports both"
 * ones matter in practice: ISO 18013-5 §8.3.3.1.1.1 says an mdoc or mdoc reader "indicates whether it supports
 * the Central role, the Peripheral role **or both**", and readers in the field (the Multipaz test app) offer
 * both BLE modes in a single carrier record that way rather than by sending two records.
 *
 * | value | meaning                                            |
 * |-------|----------------------------------------------------|
 * | 0x00  | only Peripheral supported                          |
 * | 0x01  | only Central supported                             |
 * | 0x02  | both supported, Peripheral preferred               |
 * | 0x03  | both supported, Central preferred                  |
 *
 * An unrecognised value supports neither role, which drops the carrier from consideration.
 */
class NfcBleCarrier(val serviceUuid: ByteArray?, val leRole: Int) {
    /** True when the sender can take the BLE Peripheral role (GATT server). */
    val supportsPeripheral: Boolean get() = leRole == 0x00 || leRole == 0x02 || leRole == 0x03

    /** True when the sender can take the BLE Central role (GATT client). */
    val supportsCentral: Boolean get() = leRole == 0x01 || leRole == 0x02 || leRole == 0x03
}

/**
 * A parsed ISO 18013-5 NFC negotiated Handover Request: every BLE carrier the reader offered + optional
 * ReaderEngagement. The mdoc must answer with a Select naming **one of these** (§8.2.2.1), so the mode helpers
 * below are what an mdoc consults before deciding which role to take.
 *
 * The LE Role in these records is the **reader's** own, so the two are inverted relative to the mdoc's mode:
 * a reader offering to be the Peripheral is offering *mdoc central client mode*, and one offering to be the
 * Central is offering *mdoc peripheral server mode*.
 */
class NfcHandoverRequest(val carriers: List<NfcBleCarrier>, val readerEngagement: ByteArray?) {
    /** The first carrier that names a UUID — the only address either side can dial. */
    val serviceUuid: ByteArray? get() = carriers.firstNotNullOfOrNull { it.serviceUuid }

    /**
     * The UUID to dial in **mdoc central client mode**: §8.3.3.1.1.2 defines the UUID in a Handover Request as
     * exactly that ("if the mdoc reader supports mdoc central client mode, it shall include a UUID in the
     * Handover Request message"), so it is taken from a carrier whose LE Role puts the reader in the Peripheral
     * role. Null when the reader never offered that mode, or offered it without an address.
     */
    val centralClientUuid: ByteArray? get() =
        carriers.firstOrNull { it.supportsPeripheral && it.serviceUuid != null }?.serviceUuid

    /** True when the reader offered to be the BLE Peripheral, i.e. **mdoc central client mode** is on the table. */
    val offersMdocCentralClient: Boolean get() = centralClientUuid != null

    /**
     * True when the reader offered to be the BLE Central, i.e. **mdoc peripheral server mode** is on the table.
     * That carrier needs no UUID of the reader's — the mdoc names its own in the Handover Select.
     */
    val offersMdocPeripheralServer: Boolean get() = carriers.any { it.supportsCentral }

    /**
     * The carrier an mdoc should take, or null when the Request offers no BLE mode at all.
     *
     * §8.2.2.1 lets the mdoc select **one** of the carriers the reader offered, and the reader states which it
     * would rather have twice over: by the order it lists them in (Connection Handover lists alternative
     * carriers most-preferred first) and, for a carrier that supports both roles, by the LE Role preference bit
     * (0x02 = the reader would rather be the Peripheral ⇒ *mdoc central client mode*; 0x03 = it would rather be
     * the Central ⇒ *mdoc peripheral server mode*). This walks the list in order and honours that — which is
     * also what the mdocs seen in the field do, and it is how a reader gets to steer the exchange at all.
     *
     * Where the reader expresses no preference, mdoc central client mode wins: §8.3.3.1.1.1 says a reader
     * *should* select it when the mdoc supports both, Google Wallet always picks it, and it keeps the mdoc off
     * the air — the reader advertises, the mdoc only scans.
     */
    fun selectCarrier(): NfcCarrierChoice? {
        for (carrier in carriers) {
            // The reader taking one role is the mdoc taking the other. Central client also needs an address:
            // §8.3.3.1.1.2 puts that UUID in the Request, and without it there is nothing for the mdoc to dial.
            val mdocCentralClient = carrier.supportsPeripheral && carrier.serviceUuid != null
            val mdocPeripheralServer = carrier.supportsCentral
            return when {
                mdocCentralClient && mdocPeripheralServer ->
                    if (carrier.leRole == 0x02) NfcCarrierChoice(peripheralServerMode = false, serviceUuid = carrier.serviceUuid)
                    else NfcCarrierChoice(peripheralServerMode = true, serviceUuid = null)
                mdocCentralClient -> NfcCarrierChoice(peripheralServerMode = false, serviceUuid = carrier.serviceUuid)
                mdocPeripheralServer -> NfcCarrierChoice(peripheralServerMode = true, serviceUuid = null)
                else -> continue // nothing dialable in this record — try the next carrier
            }
        }
        return null
    }
}

/**
 * The BLE mode an mdoc takes out of a negotiated Handover Request, from [NfcHandoverRequest.selectCarrier].
 * [serviceUuid] is set only for **mdoc central client mode**, where the address is the reader's; in mdoc
 * peripheral server mode the mdoc names its own UUID in the Handover Select and this is null.
 */
class NfcCarrierChoice(val peripheralServerMode: Boolean, val serviceUuid: ByteArray?)

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

    /**
     * Bluetooth CSS LE Role values, as modelled by [NfcBleCarrier]. Always the **sender's own** role, which on a
     * Handover Request inverts against the ISO mode names: mdoc central client mode has the *reader* as the
     * peripheral, so a reader asking for it sends [LE_BOTH_PERIPHERAL_PREFERRED], not the central-preferred one.
     */
    private const val LE_PERIPHERAL_ONLY = 0x00
    private const val LE_CENTRAL_ONLY = 0x01
    private const val LE_BOTH_PERIPHERAL_PREFERRED = 0x02

    /** Builds the static Handover Select NDEF message. [serviceUuid] is the 16-byte big-endian BLE service UUID. */
    fun buildHandoverSelect(deviceEngagement: ByteArray, serviceUuid: ByteArray, peripheralServerMode: Boolean = true): ByteArray {
        val hs = NdefRecord(
            Ndef.TNF_WELL_KNOWN, "Hs".toByteArray(),
            payload = byteArrayOf(HANDOVER_VERSION.toByte()) + Ndef.encodeMessage(listOf(acRecord("mdoc"))),
        )
        val de = NdefRecord(Ndef.TNF_EXTERNAL, DE_TYPE, "mdoc".toByteArray(), deviceEngagement)
        val leRole = if (peripheralServerMode) LE_PERIPHERAL_ONLY else LE_CENTRAL_ONLY
        return Ndef.encodeMessage(listOf(hs, de, bleOobRecord(serviceUuid, leRole)))
    }

    /**
     * Parses a Handover Select NDEF message on its own → the DeviceEngagement, BLE service UUID (big-endian),
     * and the mdoc's mode. Self-contained by construction, so this is the **static handover** entry point;
     * negotiated handover needs the Request too and goes through [parseHandover].
     */
    fun parseHandoverSelect(ndef: ByteArray): NfcEngagement? = parseHandover(ndef, handoverRequest = null)

    /**
     * Resolves the carrier of a finished handover: the DeviceEngagement, the UUID to dial, and which BLE mode
     * the mdoc took. The Handover Select alone does not always determine that, so pass the Handover Request
     * whenever there was one (negotiated handover); [handoverRequest] = null is static handover, where the
     * Select must be self-contained.
     *
     * Three §8.3.3.1.1 rules meet here:
     *  - The UUID's meaning depends on the message it travels in. In the **Select** it is the mdoc's own, "to
     *    be used for mdoc peripheral server mode"; in the **Request** it is the reader's, "to be used for mdoc
     *    central client mode". A Select that takes the reader's carrier therefore names no UUID at all and only
     *    the pair identifies the connection.
     *  - LE Role says which roles the **mdoc** supports, and "both" is a first-class answer (0x02 / 0x03).
     *  - When the mdoc supports both, "the mdoc reader should select the mdoc central client mode" — which also
     *    settles the UUID: mdoc central client mode dials the *reader's*, not the one in the Select. Static
     *    handover is the exception the spec calls out, where the mdoc's single UUID serves either mode.
     */
    fun parseHandover(handoverSelect: ByteArray, handoverRequest: ByteArray? = null): NfcEngagement? {
        val records = runCatching { Ndef.decodeMessage(handoverSelect) }.getOrNull() ?: return null
        if (!hasHandover(records, "Hs")) return null
        val de = records.firstOrNull { it.tnf == Ndef.TNF_EXTERNAL && it.type.contentEquals(DE_TYPE) }?.payload ?: return null
        val readerUuid = handoverRequest?.let { parseHandoverRequest(it) }?.centralClientUuid
        // The carrier the mdoc named for itself, if any; a UUID-less one carries no address to dial.
        val mdocCarrier = parseCarriers(records).firstOrNull { it.serviceUuid != null }
            ?: return readerUuid?.let { NfcEngagement(de, it, peripheralServerMode = false) }
        // Supports both + we offered mdoc central client mode → take it, on the UUID that mode belongs to.
        if (mdocCarrier.supportsPeripheral && mdocCarrier.supportsCentral && readerUuid != null) {
            return NfcEngagement(de, readerUuid, peripheralServerMode = false)
        }
        // Otherwise the mdoc's own UUID applies, and peripheral server mode is the one it named exclusively.
        val peripheralServerMode = mdocCarrier.supportsPeripheral && !mdocCarrier.supportsCentral
        return NfcEngagement(de, mdocCarrier.serviceUuid!!, peripheralServerMode)
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
     * central client — the mdoc-mode reading of the flag is inverted. [NfcHandoverRequest] exposes the same
     * sender-relative values as its `offersMdoc…` helpers. Pass `true` unless the reader intends to be the BLE central.
     *
     * [alsoOfferMdocPeripheralServer] appends a second Alternative Carrier that puts the *mdoc* in the peripheral
     * role, so an mdoc that cannot do the mode named first still has one it can take. It repeats [serviceUuid]:
     * the reader proposes the service the mdoc will then advertise, and a carrier record with no UUID is not
     * something implementations expect (the Multipaz test app dereferences it and dies). Carriers are listed in
     * the reader's order of preference — mdocs seen so far take the first one they support rather than ranking
     * them — and either reply is read the same way: a Select naming a UUID chose its own carrier, one without it
     * took the carrier offered here. Prefer [singleCarrierBothRoles]; this shape is kept for a peer that turns
     * out to need one record per mode.
     *
     * [singleCarrierBothRoles] emits the shape the spec describes, and is what the reader adapter sends:
     * **one** BLE carrier whose LE Role says "both supported, Peripheral preferred" (0x02) — the reader would
     * rather be the peripheral, i.e. it prefers mdoc central client mode, but will take either. §8.3.3.1.1.1
     * treats "or both" as a first-class answer, §8.2.2.1's carrier granularity is the *transmission technology*
     * (BLE) rather than the role, and the Multipaz reader encodes its own offer this way. It also removes the
     * duplicated UUID that [alsoOfferMdocPeripheralServer] has to send: a Request's UUID is defined as the
     * mdoc-central-client one, and the mdoc names its own for peripheral server mode.
     *
     * Device-measured 2026-08-22: Google Wallet and this SDK's own holder both read the preference bit and take
     * mdoc central client mode; the Multipaz holder ignores it and answers with peripheral server, which
     * completes just as well. Takes precedence over the two-carrier flags.
     */
    fun buildHandoverRequest(
        serviceUuid: ByteArray,
        collisionResolution: ByteArray,
        peripheralServerMode: Boolean = true,
        readerEngagement: ByteArray? = null,
        alsoOfferMdocPeripheralServer: Boolean = false,
        singleCarrierBothRoles: Boolean = false,
    ): ByteArray {
        val carriers = if (singleCarrierBothRoles) {
            // Sender-relative: "I would rather be the Peripheral" is this reader asking for mdoc central client mode.
            mutableListOf(bleOobRecord(serviceUuid, LE_BOTH_PERIPHERAL_PREFERRED, id = "0"))
        } else {
            mutableListOf(bleOobRecord(serviceUuid, if (peripheralServerMode) LE_PERIPHERAL_ONLY else LE_CENTRAL_ONLY, id = "0")).also {
                if (alsoOfferMdocPeripheralServer) it.add(bleOobRecord(serviceUuid, LE_CENTRAL_ONLY, id = "1"))
            }
        }
        val auxRef = readerEngagement?.let { "mdocreader" }
        val cr = NdefRecord(Ndef.TNF_WELL_KNOWN, "cr".toByteArray(), payload = collisionResolution)
        val hr = NdefRecord(
            Ndef.TNF_WELL_KNOWN, "Hr".toByteArray(),
            payload = byteArrayOf(HANDOVER_VERSION.toByte()) +
                Ndef.encodeMessage(listOf(cr) + carriers.mapIndexed { i, _ -> acRecord(auxRef, carrierRef = i.toString()) }),
        )
        val records = mutableListOf(hr)
        readerEngagement?.let { records.add(NdefRecord(Ndef.TNF_EXTERNAL, RE_TYPE, "mdocreader".toByteArray(), it)) }
        records.addAll(carriers)
        return Ndef.encodeMessage(records)
    }

    /** Parses a negotiated Handover Request NDEF message → every BLE carrier it offers + optional ReaderEngagement. */
    fun parseHandoverRequest(ndef: ByteArray): NfcHandoverRequest? {
        val records = runCatching { Ndef.decodeMessage(ndef) }.getOrNull() ?: return null
        if (!hasHandover(records, "Hr")) return null
        val carriers = parseCarriers(records)
        if (carriers.isEmpty()) return null
        val re = records.firstOrNull { it.tnf == Ndef.TNF_EXTERNAL && it.type.contentEquals(RE_TYPE) }?.payload
        return NfcHandoverRequest(carriers, re)
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

    /** An Alternative Carrier record: active carrier, its carrier-data reference, optional single aux-data reference. */
    private fun acRecord(auxRef: String?, carrierRef: String = "0"): NdefRecord {
        val head = byteArrayOf(0x01, carrierRef.length.toByte()) + carrierRef.toByteArray() // CPS=active + carrier-data-ref
        val aux = auxRef?.let { byteArrayOf(0x01, it.length.toByte()) + it.toByteArray() } ?: byteArrayOf(0x00)
        return NdefRecord(Ndef.TNF_WELL_KNOWN, "ac".toByteArray(), payload = head + aux)
    }

    /** BLE carrier-config record: [leRole] + the 128-bit service UUID written little-endian, under record id [id]. */
    private fun bleOobRecord(serviceUuid: ByteArray, leRole: Int, id: String = "0"): NdefRecord =
        NdefRecord(
            Ndef.TNF_MIME_MEDIA, OOB_MIME, id.toByteArray(),
            byteArrayOf(0x02, AD_LE_ROLE.toByte(), leRole.toByte(), 0x11, AD_UUID128.toByte()) + serviceUuid.reversedArray(),
        )

    /**
     * Reads every BLE carrier-configuration record in the message, in the order the sender listed them (which
     * is its order of preference). A message may carry several — one per mode, or one that names both roles —
     * and either side has to see all of them to know what was actually offered.
     *
     * LE Role is mandatory (§8.3.3.1.1.2) but defaults to Peripheral-only when absent, because that is what a
     * bare UUID means in both messages: the mdoc naming its own is peripheral server mode, and the reader
     * naming its own is the reader being the peripheral. Unknown AD types are skipped, as the spec allows
     * ("Other data types may be included in the OOB data block").
     */
    private fun parseCarriers(records: List<NdefRecord>): List<NfcBleCarrier> =
        records.filter { it.tnf == Ndef.TNF_MIME_MEDIA && it.type.contentEquals(OOB_MIME) }.map { oob ->
            var i = 0
            var leRole = 0x00
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
            NfcBleCarrier(uuid, leRole)
        }
}
