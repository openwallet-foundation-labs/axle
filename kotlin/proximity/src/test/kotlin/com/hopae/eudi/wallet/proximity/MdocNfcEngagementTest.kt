package com.hopae.eudi.wallet.proximity

import com.hopae.eudi.wallet.cbor.Cbor
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class MdocNfcEngagementTest {
    @Test
    fun ndefRoundTrip() {
        val records = listOf(
            NdefRecord(Ndef.TNF_WELL_KNOWN, "Hs".toByteArray(), payload = byteArrayOf(0x15)),
            NdefRecord(Ndef.TNF_EXTERNAL, "iso.org:18013:deviceengagement".toByteArray(), "mdoc".toByteArray(), ByteArray(300) { it.toByte() }),
        )
        val decoded = Ndef.decodeMessage(Ndef.encodeMessage(records))
        assertContentEquals(records[1].payload, decoded[1].payload) // 300-byte payload → long-record path
        assertContentEquals("mdoc".toByteArray(), decoded[1].id)
    }

    @Test
    fun handoverSelectRoundTrip() {
        val engagement = byteArrayOf(0xA2.toByte(), 0x00, 0x63, 0x31, 0x2E, 0x30) // arbitrary DeviceEngagement bytes
        val uuid = ByteArray(16) { (it + 1).toByte() }

        val hs = MdocNfcEngagement.buildHandoverSelect(engagement, uuid, peripheralServerMode = true)
        val parsed = MdocNfcEngagement.parseHandoverSelect(hs)
        assertNotNull(parsed)
        assertContentEquals(engagement, parsed.deviceEngagement)
        assertContentEquals(uuid, parsed.serviceUuid) // little-endian OOB → back to canonical big-endian
        assertTrue(parsed.peripheralServerMode)
    }

    @Test
    fun handoverRequestRoundTrip() {
        val uuid = ByteArray(16) { (it + 1).toByte() }
        val cr = byteArrayOf(0x12, 0x34)
        val re = MdocNfcEngagement.readerEngagement("1.0")

        val hr = MdocNfcEngagement.buildHandoverRequest(uuid, cr, peripheralServerMode = false, readerEngagement = re)
        val parsed = MdocNfcEngagement.parseHandoverRequest(hr)
        assertNotNull(parsed)
        assertContentEquals(uuid, parsed.serviceUuid)
        assertTrue(parsed.offersMdocPeripheralServer) // the reader is the central ⇒ the mdoc is the peripheral
        assertFalse(parsed.offersMdocCentralClient)
        assertContentEquals(re, parsed.readerEngagement)

        // A static Handover Select must not parse as a Handover Request, and vice versa.
        assertNull(MdocNfcEngagement.parseHandoverRequest(MdocNfcEngagement.buildHandoverSelect(byteArrayOf(0xA0.toByte()), uuid)))
        assertNull(MdocNfcEngagement.parseHandoverSelect(hr))
    }

    @Test
    fun handoverRequestWithoutReaderEngagement() {
        val uuid = ByteArray(16) { (it + 1).toByte() }
        val hr = MdocNfcEngagement.buildHandoverRequest(uuid, byteArrayOf(0x00, 0x01))
        val parsed = MdocNfcEngagement.parseHandoverRequest(hr)
        assertNotNull(parsed)
        assertNull(parsed.readerEngagement)
        assertTrue(parsed.offersMdocCentralClient) // default: the reader is the peripheral
        assertFalse(parsed.offersMdocPeripheralServer)
    }

    /** §8.3.3.1.1.2: a Select that takes the reader's carrier names no UUID — it is the one from the Request. */
    @Test
    fun negotiatedSelectWithoutCarrierUsesTheRequestUuid() {
        val engagement = byteArrayOf(0xA2.toByte(), 0x00, 0x63, 0x31, 0x2E, 0x30)
        val uuid = ByteArray(16) { (it + 1).toByte() }
        val hs = Ndef.encodeMessage(
            listOf(
                NdefRecord(Ndef.TNF_WELL_KNOWN, "Hs".toByteArray(), payload = byteArrayOf(0x15)),
                NdefRecord(Ndef.TNF_EXTERNAL, "iso.org:18013:deviceengagement".toByteArray(), "mdoc".toByteArray(), engagement),
            ),
        )
        assertNull(MdocNfcEngagement.parseHandoverSelect(hs)) // not self-contained…
        assertNull(MdocNfcEngagement.parseHandover(hs)) // …and static handover has no Request to fall back on

        val hr = MdocNfcEngagement.buildHandoverRequest(uuid, byteArrayOf(0x12, 0x34), peripheralServerMode = true)
        val parsed = assertNotNull(MdocNfcEngagement.parseHandover(hs, hr))
        assertContentEquals(engagement, parsed.deviceEngagement)
        assertContentEquals(uuid, parsed.serviceUuid)
        assertTrue(!parsed.peripheralServerMode) // the reader is the peripheral ⇒ mdoc central client mode

        // A reader offering to be the central has no UUID to lend — that mode's UUID is the mdoc's to name.
        val central = MdocNfcEngagement.buildHandoverRequest(uuid, byteArrayOf(0x12, 0x34), peripheralServerMode = false)
        assertNull(MdocNfcEngagement.parseHandover(hs, central))
    }

    /** Offering both modes: a second, UUID-less carrier lets the mdoc answer as the peripheral if it prefers. */
    @Test
    fun handoverRequestCanOfferBothModes() {
        val uuid = ByteArray(16) { (it + 1).toByte() }
        val hr = MdocNfcEngagement.buildHandoverRequest(uuid, byteArrayOf(0x12, 0x34), alsoOfferMdocPeripheralServer = true)
        val records = Ndef.decodeMessage(hr)

        // The reader's own carrier is still the one either side can dial…
        val parsed = assertNotNull(MdocNfcEngagement.parseHandoverRequest(hr))
        assertContentEquals(uuid, parsed.serviceUuid)
        assertTrue(parsed.offersMdocCentralClient)
        assertTrue(parsed.offersMdocPeripheralServer)

        // …and the offer for the mdoc to be the peripheral rides along under its own record id, repeating the UUID:
        // that is the service the reader proposes the mdoc advertise, and carriers without one are not expected.
        val carriers = records.filter { it.tnf == Ndef.TNF_MIME_MEDIA }
        assertEquals(2, carriers.size)
        assertContentEquals("1".toByteArray(), carriers[1].id)
        assertContentEquals(byteArrayOf(0x02, 0x1C, 0x01, 0x11, 0x07) + uuid.reversedArray(), carriers[1].payload)

        // Each carrier needs an Alternative Carrier record pointing at it, or the mdoc cannot select it.
        val hrPayload = records.first { it.type.contentEquals("Hr".toByteArray()) }.payload
        val acs = Ndef.decodeMessage(hrPayload.copyOfRange(1, hrPayload.size)).filter { it.type.contentEquals("ac".toByteArray()) }
        assertContentEquals(listOf("0", "1"), acs.map { String(it.payload.copyOfRange(2, 2 + it.payload[1].toInt())) })
    }

    /** The mdoc's own carrier stays authoritative whenever its Select carries one. */
    @Test
    fun selectCarrierOutranksTheRequestCarrier() {
        val mdocUuid = ByteArray(16) { (it + 1).toByte() }
        val readerUuid = ByteArray(16) { (0x80 + it).toByte() }
        val hs = MdocNfcEngagement.buildHandoverSelect(byteArrayOf(0xA0.toByte()), mdocUuid, peripheralServerMode = true)
        val hr = MdocNfcEngagement.buildHandoverRequest(readerUuid, byteArrayOf(0x00, 0x01), peripheralServerMode = true)

        val parsed = assertNotNull(MdocNfcEngagement.parseHandover(hs, hr))
        assertContentEquals(mdocUuid, parsed.serviceUuid)
        assertTrue(parsed.peripheralServerMode)
    }

    /** §9.1.5.1: static handover binds `[Hs, null]`; negotiated binds `[Hs, Hr]`. */
    @Test
    fun sessionTranscriptHandoverShapes() {
        val hs = byteArrayOf(0x01, 0x02, 0x03)
        val hr = byteArrayOf(0x0A, 0x0B)

        val static = ProximitySessionTranscript.nfcHandover(hs) as Cbor.Array
        assertContentEquals(hs, (static.items[0] as Cbor.Bytes).value)
        assertEquals(Cbor.Null, static.items[1])

        val negotiated = ProximitySessionTranscript.nfcHandover(hs, hr) as Cbor.Array
        assertContentEquals(hs, (negotiated.items[0] as Cbor.Bytes).value)
        assertContentEquals(hr, (negotiated.items[1] as Cbor.Bytes).value)
    }

    /**
     * §8.3.3.1.1.1: a reader may say it supports "both" roles in a single carrier, via LE Role 0x02 / 0x03,
     * instead of sending one carrier per mode. The Multipaz test app's reader encodes its offer exactly this
     * way, so both BLE modes have to come out of one record.
     */
    @Test
    fun readerCarrierCanOfferBothRolesInOneRecord() {
        val uuid = ByteArray(16) { (it + 1).toByte() }
        for (leRole in listOf(0x02, 0x03)) {
            val parsed = assertNotNull(MdocNfcEngagement.parseHandoverRequest(handoverRequestWithLeRole(uuid, leRole)))
            assertContentEquals(uuid, parsed.serviceUuid)
            assertTrue(parsed.offersMdocCentralClient, "LE Role $leRole offers the reader as peripheral")
            assertTrue(parsed.offersMdocPeripheralServer, "LE Role $leRole offers the reader as central")
            assertContentEquals(uuid, parsed.centralClientUuid)
        }
    }

    /** An unrecognised LE Role supports neither role, so the carrier is not something either side can take. */
    @Test
    fun unknownLeRoleOffersNothing() {
        val uuid = ByteArray(16) { (it + 1).toByte() }
        val parsed = assertNotNull(MdocNfcEngagement.parseHandoverRequest(handoverRequestWithLeRole(uuid, 0x7F)))
        assertFalse(parsed.offersMdocCentralClient)
        assertFalse(parsed.offersMdocPeripheralServer)
    }

    /**
     * A Select whose LE Role says "both": §8.3.3.1.1.1 has the reader select mdoc central client mode, and that
     * mode's UUID is the reader's own from the Request — not the one in the Select, which §8.3.3.1.1.2 reserves
     * for mdoc peripheral server mode. Pairing the Select's UUID with central client mode would leave the reader
     * serving an address the mdoc never scans for.
     */
    @Test
    fun selectOfferingBothRolesTakesCentralClientOnTheReaderUuid() {
        val mdocUuid = ByteArray(16) { (it + 1).toByte() }
        val readerUuid = ByteArray(16) { (0x80 + it).toByte() }
        val hs = handoverSelectWithLeRole(mdocUuid, 0x02)
        val hr = MdocNfcEngagement.buildHandoverRequest(readerUuid, byteArrayOf(0x12, 0x34), peripheralServerMode = true)

        val parsed = assertNotNull(MdocNfcEngagement.parseHandover(hs, hr))
        assertContentEquals(readerUuid, parsed.serviceUuid)
        assertFalse(parsed.peripheralServerMode)
    }

    /** Static handover has no Request, and §8.3.3.1.1.2 lets the mdoc's single UUID serve either mode. */
    @Test
    fun staticSelectOfferingBothRolesUsesItsOwnUuid() {
        val mdocUuid = ByteArray(16) { (it + 1).toByte() }
        val parsed = assertNotNull(MdocNfcEngagement.parseHandoverSelect(handoverSelectWithLeRole(mdocUuid, 0x03)))
        assertContentEquals(mdocUuid, parsed.serviceUuid)
        assertFalse(parsed.peripheralServerMode) // both supported ⇒ the reader picks mdoc central client mode
    }

    /** The UUID-less-Select fallback has to work against a reader that offered both roles in one carrier too. */
    @Test
    fun selectWithoutCarrierFallsBackToABothRoleRequest() {
        val engagement = byteArrayOf(0xA2.toByte(), 0x00, 0x63, 0x31, 0x2E, 0x30)
        val readerUuid = ByteArray(16) { (0x80 + it).toByte() }
        val hs = Ndef.encodeMessage(
            listOf(
                NdefRecord(Ndef.TNF_WELL_KNOWN, "Hs".toByteArray(), payload = byteArrayOf(0x15)),
                NdefRecord(Ndef.TNF_EXTERNAL, "iso.org:18013:deviceengagement".toByteArray(), "mdoc".toByteArray(), engagement),
            ),
        )
        val parsed = assertNotNull(MdocNfcEngagement.parseHandover(hs, handoverRequestWithLeRole(readerUuid, 0x03)))
        assertContentEquals(readerUuid, parsed.serviceUuid)
        assertFalse(parsed.peripheralServerMode)
    }

    /** A BLE carrier-configuration record with an arbitrary raw LE Role value, which the builders cannot emit. */
    private fun bleOob(uuid: ByteArray, leRole: Int, id: String = "0"): NdefRecord = NdefRecord(
        Ndef.TNF_MIME_MEDIA, "application/vnd.bluetooth.le.oob".toByteArray(), id.toByteArray(),
        byteArrayOf(0x02, 0x1C, leRole.toByte(), 0x11, 0x07) + uuid.reversedArray(),
    )

    private fun handoverRequestWithLeRole(uuid: ByteArray, leRole: Int): ByteArray {
        val ac = NdefRecord(Ndef.TNF_WELL_KNOWN, "ac".toByteArray(), payload = byteArrayOf(0x01, 0x01) + "0".toByteArray() + byteArrayOf(0x00))
        val cr = NdefRecord(Ndef.TNF_WELL_KNOWN, "cr".toByteArray(), payload = byteArrayOf(0x12, 0x34))
        val hr = NdefRecord(
            Ndef.TNF_WELL_KNOWN, "Hr".toByteArray(),
            payload = byteArrayOf(0x15) + Ndef.encodeMessage(listOf(cr, ac)),
        )
        return Ndef.encodeMessage(listOf(hr, bleOob(uuid, leRole)))
    }

    private fun handoverSelectWithLeRole(uuid: ByteArray, leRole: Int): ByteArray {
        val ac = NdefRecord(Ndef.TNF_WELL_KNOWN, "ac".toByteArray(), payload = byteArrayOf(0x01, 0x01) + "0".toByteArray() + byteArrayOf(0x01, 0x04) + "mdoc".toByteArray())
        val hs = NdefRecord(Ndef.TNF_WELL_KNOWN, "Hs".toByteArray(), payload = byteArrayOf(0x15) + Ndef.encodeMessage(listOf(ac)))
        val de = NdefRecord(Ndef.TNF_EXTERNAL, "iso.org:18013:deviceengagement".toByteArray(), "mdoc".toByteArray(), byteArrayOf(0xA0.toByte()))
        return Ndef.encodeMessage(listOf(hs, de, bleOob(uuid, leRole)))
    }

    /**
     * The mdoc follows the reader's stated preference — list order first, then the LE Role bit for a carrier
     * that supports both roles. Getting this wrong is invisible until a reader that only implements one mode
     * refuses the Select, so it is pinned per shape.
     */
    @Test
    fun carrierSelectionFollowsTheReadersPreference() {
        val uuid = ByteArray(16) { (it + 1).toByte() }

        // Our own reader's shape: mdoc central client listed first, mdoc peripheral server second.
        val ours = assertNotNull(MdocNfcEngagement.parseHandoverRequest(
            MdocNfcEngagement.buildHandoverRequest(uuid, byteArrayOf(0x12, 0x34), alsoOfferMdocPeripheralServer = true),
        )!!.selectCarrier())
        assertFalse(ours.peripheralServerMode)
        assertContentEquals(uuid, ours.serviceUuid)

        // …and reversed, the same reader would get mdoc peripheral server, where the mdoc names its own UUID.
        val reversed = assertNotNull(MdocNfcEngagement.parseHandoverRequest(
            MdocNfcEngagement.buildHandoverRequest(uuid, byteArrayOf(0x12, 0x34), peripheralServerMode = false),
        )!!.selectCarrier())
        assertTrue(reversed.peripheralServerMode)
        assertNull(reversed.serviceUuid)

        // One carrier, both roles: 0x02 = the reader prefers Peripheral ⇒ mdoc central client…
        val bothPeripheralPreferred = assertNotNull(
            MdocNfcEngagement.parseHandoverRequest(handoverRequestWithLeRole(uuid, 0x02))!!.selectCarrier(),
        )
        assertFalse(bothPeripheralPreferred.peripheralServerMode)
        assertContentEquals(uuid, bothPeripheralPreferred.serviceUuid)

        // …and 0x03 = it prefers Central ⇒ mdoc peripheral server. This is what the Multipaz reader sends.
        val bothCentralPreferred = assertNotNull(
            MdocNfcEngagement.parseHandoverRequest(handoverRequestWithLeRole(uuid, 0x03))!!.selectCarrier(),
        )
        assertTrue(bothCentralPreferred.peripheralServerMode)
        assertNull(bothCentralPreferred.serviceUuid)

        // A Request offering no BLE role at all leaves the mdoc nothing to select.
        assertNull(MdocNfcEngagement.parseHandoverRequest(handoverRequestWithLeRole(uuid, 0x7F))!!.selectCarrier())
    }


    /**
     * The shape §8.2.2.1 + §8.3.3.1.1.1 describe: one BLE carrier (an alternative carrier is a *transmission
     * technology*), whose LE Role says which roles the reader supports and which it would rather have.
     */
    @Test
    fun handoverRequestCanOfferBothRolesInOneCarrier() {
        val uuid = ByteArray(16) { (it + 1).toByte() }
        val hr = MdocNfcEngagement.buildHandoverRequest(uuid, byteArrayOf(0x12, 0x34), singleCarrierBothRoles = true)

        val carriers = Ndef.decodeMessage(hr).filter { it.tnf == Ndef.TNF_MIME_MEDIA }
        assertEquals(1, carriers.size)
        assertContentEquals(byteArrayOf(0x02, 0x1C, 0x02, 0x11, 0x07) + uuid.reversedArray(), carriers[0].payload)

        val parsed = assertNotNull(MdocNfcEngagement.parseHandoverRequest(hr))
        assertTrue(parsed.offersMdocCentralClient)
        assertTrue(parsed.offersMdocPeripheralServer)

        // LE Role 0x02 = the reader prefers to be the peripheral, so an mdoc takes central client mode.
        val choice = assertNotNull(parsed.selectCarrier())
        assertFalse(choice.peripheralServerMode)
        assertContentEquals(uuid, choice.serviceUuid)
    }
}
