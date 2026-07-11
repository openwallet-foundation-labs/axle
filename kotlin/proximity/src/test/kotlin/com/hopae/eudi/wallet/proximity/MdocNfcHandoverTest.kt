package com.hopae.eudi.wallet.proximity

import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Loopback of the NFC handover transport: the reader driver ([MdocNfcHandover]) talks to the holder state
 * machine ([NfcEngagementProcessor]) in-process, so the full APDU / TNEP choreography is exercised without
 * a device. Covers static (read-only) and negotiated (TNEP: Service Select → status → Hr↔Hs) handover.
 */
class MdocNfcHandoverTest {
    private val engagement = byteArrayOf(1, 2, 3, 4, 5) // opaque DeviceEngagement stand-in
    private val serviceUuid = ByteArray(16) { (it + 1).toByte() }

    private fun holderHs(): ByteArray = MdocNfcEngagement.buildHandoverSelect(engagement, serviceUuid, peripheralServerMode = true)

    @Test
    fun `static handover returns the Handover Select with no request`() = runTest {
        val processor = NfcEngagementProcessor(staticHandoverSelect = holderHs())
        val hr = MdocNfcEngagement.buildHandoverRequest(serviceUuid, collisionResolution = byteArrayOf(0x11, 0x22))

        val result = MdocNfcHandover.read(hr) { processor.processCommand(it) }

        assertNull(result.handoverRequest, "static handover binds no Handover Request")
        assertContentEquals(holderHs(), result.handoverSelect)
        val parsed = assertNotNull(MdocNfcEngagement.parseHandoverSelect(result.handoverSelect))
        assertContentEquals(engagement, parsed.deviceEngagement)
    }

    @Test
    fun `static handover rejects writes (read-only NDEF file)`() = runTest {
        val processor = NfcEngagementProcessor(staticHandoverSelect = holderHs())
        // UPDATE BINARY (INS 0xD6) at offset 0 must be refused with a non-success status word.
        val resp = processor.processCommand(byteArrayOf(0x00, 0xD6.toByte(), 0x00, 0x00, 0x02, 0x00, 0x00))
        val sw = ((resp[resp.size - 2].toInt() and 0xFF) shl 8) or (resp[resp.size - 1].toInt() and 0xFF)
        assertEquals(Nfc.SW_FILE_NOT_FOUND, sw)
    }

    @Test
    fun `negotiated handover runs the TNEP exchange and binds the reader's request`() = runTest {
        var seenHr: ByteArray? = null
        val processor = NfcEngagementProcessor(
            negotiatedHandoverSelect = { hr ->
                seenHr = hr // the exact Handover Request the reader wrote — the holder binds these bytes
                holderHs()
            },
        )
        val hr = MdocNfcEngagement.buildHandoverRequest(
            serviceUuid, collisionResolution = byteArrayOf(0x12, 0x34), readerEngagement = MdocNfcEngagement.readerEngagement(),
        )

        val result = MdocNfcHandover.read(hr) { processor.processCommand(it) }

        assertTrue(result.negotiated, "TNEP Service Parameter must drive negotiated handover")
        assertContentEquals(hr, result.handoverRequest, "reader binds the same Hr it sent")
        assertContentEquals(hr, seenHr, "holder is handed the exact Hr bytes to bind")
        assertContentEquals(holderHs(), result.handoverSelect)
        val parsed = assertNotNull(MdocNfcEngagement.parseHandoverSelect(result.handoverSelect))
        assertContentEquals(engagement, parsed.deviceEngagement)
    }

    @Test
    fun `holder resets negotiated state between taps`() = runTest {
        val processor = NfcEngagementProcessor(negotiatedHandoverSelect = { holderHs() })
        val hr = MdocNfcEngagement.buildHandoverRequest(serviceUuid, collisionResolution = byteArrayOf(1, 2))
        assertTrue(MdocNfcHandover.read(hr) { processor.processCommand(it) }.negotiated)
        processor.reset()
        // A second tap must complete the TNEP exchange again from a clean state.
        val second = MdocNfcHandover.read(hr) { processor.processCommand(it) }
        assertContentEquals(holderHs(), second.handoverSelect)
    }
}
