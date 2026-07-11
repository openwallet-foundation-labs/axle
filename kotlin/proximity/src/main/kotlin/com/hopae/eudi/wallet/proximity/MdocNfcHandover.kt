package com.hopae.eudi.wallet.proximity

import kotlinx.coroutines.delay

/** The outcome of NFC engagement as a reader: the Handover Select, plus the Handover Request iff negotiated (else null). */
class NfcHandover(val handoverSelect: ByteArray, val handoverRequest: ByteArray?) {
    val negotiated: Boolean get() = handoverRequest != null
}

/**
 * The reader/verifier side of ISO/IEC 18013-5 NFC engagement over an NFC Forum Type 4 Tag. Given a [transceive]
 * that sends a command APDU and returns the response APDU, it selects the NDEF application, reads the initial
 * NDEF message, and **auto-detects** the handover mode (§8.2.2): a TNEP Service Parameter record for the
 * Connection Handover service means negotiated handover, otherwise static.
 *
 * For negotiated handover it runs the TNEP exchange (Service Select → TNEP Status → write [handoverRequest] →
 * read Handover Select) and returns both messages so the caller can bind `[Hs, Hr]` into the SessionTranscript;
 * for static handover it returns the Handover Select with a null request. Transport-agnostic (no Android types).
 */
object MdocNfcHandover {
    /**
     * @param handoverRequest the Handover Request NDEF message to send if the mdoc offers negotiated handover
     *   (e.g. from [MdocNfcEngagement.buildHandoverRequest]); ignored for static handover.
     * @param transceive sends a command APDU and returns the response APDU (data + 2-byte status word).
     */
    suspend fun read(handoverRequest: ByteArray, transceive: suspend (ByteArray) -> ByteArray): NfcHandover {
        val io = Io(transceive)
        io.selectApplication(Nfc.NDEF_APPLICATION_ID)
        io.selectFile(Nfc.CC_FILE_ID)
        val cc = io.readBinary(0, 15)
        val ndefFileId = ((cc[9].toInt() and 0xFF) shl 8) or (cc[10].toInt() and 0xFF)
        io.selectFile(ndefFileId)

        val initial = io.ndefReadMessage(wtInt = 0, nWait = 0)
        val serviceParameter = Ndef.decodeMessage(initial)
            .firstNotNullOfOrNull { Tnep.parseServiceParameter(it) }
            ?.takeIf { it.serviceNameUri == Nfc.SERVICE_NAME_HANDOVER }
            ?: return NfcHandover(initial, null) // no TNEP → static handover

        // Negotiated handover: select the Connection Handover service, confirm the TNEP status, then swap Hr↔Hs.
        val statusMessage = io.ndefTransact(
            Ndef.encodeMessage(listOf(Tnep.serviceSelectRecord())), serviceParameter.wtInt, serviceParameter.nWait,
        )
        val status = Ndef.decodeMessage(statusMessage).firstNotNullOfOrNull { Tnep.parseTnepStatus(it) }
            ?: throw IllegalStateException("negotiated handover: no TNEP status record")
        if (status != 0x00) throw IllegalStateException("negotiated handover: TNEP status $status")

        val handoverSelect = io.ndefTransact(handoverRequest, serviceParameter.wtInt, serviceParameter.nWait)
        return NfcHandover(handoverSelect, handoverRequest)
    }

    /** ISO 7816-4 / Type 4 Tag command builders + the TNEP read/transact helpers over a raw [transceive]. */
    private class Io(private val transceive: suspend (ByteArray) -> ByteArray) {
        suspend fun selectApplication(aid: ByteArray) {
            val r = send(byteArrayOf(0x00, Nfc.INS_SELECT.toByte(), Nfc.SELECT_P1_APPLICATION.toByte(), 0x00, aid.size.toByte()) + aid + byteArrayOf(0x00))
            check(status(r) == Nfc.SW_SUCCESS) { "SELECT application failed: ${hexSw(r)}" }
        }

        suspend fun selectFile(fileId: Int) {
            val r = send(byteArrayOf(0x00, Nfc.INS_SELECT.toByte(), Nfc.SELECT_P1_FILE.toByte(), 0x0C, 0x02, (fileId shr 8).toByte(), (fileId and 0xFF).toByte()))
            check(status(r) == Nfc.SW_SUCCESS) { "SELECT file ${fileId.toString(16)} failed: ${hexSw(r)}" }
        }

        suspend fun readBinary(offset: Int, length: Int): ByteArray {
            val r = send(byteArrayOf(0x00, Nfc.INS_READ_BINARY.toByte(), (offset shr 8).toByte(), (offset and 0xFF).toByte(), length.toByte()))
            check(status(r) == Nfc.SW_SUCCESS) { "READ BINARY failed: ${hexSw(r)}" }
            return r.copyOfRange(0, r.size - 2)
        }

        private suspend fun updateBinary(offset: Int, data: ByteArray) {
            val r = send(byteArrayOf(0x00, Nfc.INS_UPDATE_BINARY.toByte(), (offset shr 8).toByte(), (offset and 0xFF).toByte(), data.size.toByte()) + data)
            check(status(r) == Nfc.SW_SUCCESS) { "UPDATE BINARY failed: ${hexSw(r)}" }
        }

        /** Reads the NDEF message (NLEN then body), honoring the TNEP wait-time-extension retry if NLEN is 0. */
        suspend fun ndefReadMessage(wtInt: Int, nWait: Int): ByteArray {
            var waitsLeft = nWait
            while (true) {
                val nlen = readBinary(0, 2)
                val len = ((nlen[0].toInt() and 0xFF) shl 8) or (nlen[1].toInt() and 0xFF)
                if (len > 0) {
                    val out = java.io.ByteArrayOutputStream()
                    var offset = 2
                    var remaining = len
                    while (remaining > 0) {
                        val chunk = minOf(remaining, 0xF0)
                        out.write(readBinary(offset, chunk))
                        offset += chunk; remaining -= chunk
                    }
                    return out.toByteArray()
                }
                check(waitsLeft-- > 0) { "NDEF length 0 with no TNEP wait extensions left" }
                delay(waitMillis(wtInt))
            }
        }

        /** Type 4 Tag §7.5.5 write procedure followed by a read — one TNEP request/response round trip. */
        suspend fun ndefTransact(message: ByteArray, wtInt: Int, nWait: Int): ByteArray {
            if (message.size < 254) {
                updateBinary(0, byteArrayOf((message.size shr 8).toByte(), (message.size and 0xFF).toByte()) + message)
            } else {
                updateBinary(0, byteArrayOf(0x00, 0x00))
                var offset = 0
                while (offset < message.size) {
                    val n = minOf(message.size - offset, 255)
                    updateBinary(offset + 2, message.copyOfRange(offset, offset + n))
                    offset += n
                }
                updateBinary(0, byteArrayOf((message.size shr 8).toByte(), (message.size and 0xFF).toByte()))
            }
            return ndefReadMessage(wtInt, nWait)
        }

        private suspend fun send(apdu: ByteArray): ByteArray = transceive(apdu)
        private fun status(r: ByteArray): Int = ((r[r.size - 2].toInt() and 0xFF) shl 8) or (r[r.size - 1].toInt() and 0xFF)
        private fun hexSw(r: ByteArray): String = "%04x".format(status(r))
        // TNEP minimum waiting time is tiny (sub-ms at wtInt 0); the holder blocks the write until ready, so a 2ms floor suffices.
        private fun waitMillis(wtInt: Int): Long = maxOf(2L, (Math.pow(2.0, (wtInt / 4 - 1).toDouble()) / 1000.0 * 1000).toLong())
    }
}
