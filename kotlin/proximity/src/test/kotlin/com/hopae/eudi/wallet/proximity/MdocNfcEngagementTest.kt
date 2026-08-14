package com.hopae.eudi.wallet.proximity

import com.hopae.eudi.wallet.cbor.Cbor
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
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
        assertTrue(!parsed.peripheralServerMode) // central client mode
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
        assertTrue(parsed.peripheralServerMode) // default
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
}
