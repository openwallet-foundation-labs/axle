package com.hopae.eudi.wallet.proximity

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertNotNull
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
}
