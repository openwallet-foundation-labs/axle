package com.hopae.eudi.wallet.proximity

/**
 * The mdoc (holder) side of ISO/IEC 18013-5 NFC engagement, as an APDU state machine over an NFC Forum
 * **Type 4 Tag** (Host Card Emulation). A platform transport feeds command APDUs to [processCommand] and
 * calls [reset] on deactivation; this class serves the Capability Container, the NDEF file, and — for
 * negotiated handover — drives the TNEP exchange. It is transport-agnostic (no Android types).
 *
 * Exactly one handover mode is offered per session (the reader adapts to whichever it finds, §8.2.2):
 *  - **static** ([staticHandoverSelect] set): the NDEF file directly serves the Handover Select message.
 *  - **negotiated** ([negotiatedHandoverSelect] set): the NDEF file first serves a TNEP Service Parameter
 *    record; the reader selects the Connection Handover service, then writes its Handover Request, and this
 *    class calls [negotiatedHandoverSelect] with those exact bytes to obtain the Handover Select to return.
 *
 * [negotiatedHandoverSelect] is `suspend` because producing the Handover Select typically means starting the
 * wallet's presentation (which binds `[Hs, Hr]` into the SessionTranscript); the caller returns the encoded
 * Handover Select NDEF message. The reader's Handover Request bytes passed to it are the exact bytes to bind.
 */
class NfcEngagementProcessor(
    private val staticHandoverSelect: ByteArray? = null,
    private val negotiatedHandoverSelect: (suspend (handoverRequest: ByteArray) -> ByteArray)? = null,
) {
    init {
        require((staticHandoverSelect != null) != (negotiatedHandoverSelect != null)) {
            "Provide exactly one of staticHandoverSelect or negotiatedHandoverSelect"
        }
    }

    private val negotiated = negotiatedHandoverSelect != null

    private enum class Phase { NOT_STARTED, EXPECT_SERVICE_SELECT, EXPECT_HANDOVER_REQUEST, DONE }

    private var applicationSelected = false
    private var selectedFile: ByteArray? = null
    private var tnepState = Phase.NOT_STARTED
    private var writeBuffer: ByteArrayBuilder? = null

    /** Processes one command APDU and returns the response APDU (data + SW). Suspends while building the negotiated Select. */
    suspend fun processCommand(apdu: ByteArray): ByteArray {
        if (apdu.size < 4) return sw(Nfc.SW_WRONG_LENGTH)
        return when (apdu[1].toInt() and 0xFF) {
            Nfc.INS_SELECT -> handleSelect(apdu)
            Nfc.INS_READ_BINARY -> handleReadBinary(apdu)
            Nfc.INS_UPDATE_BINARY -> handleUpdateBinary(apdu)
            else -> sw(Nfc.SW_INS_NOT_SUPPORTED)
        }
    }

    /** Resets per-tap state; call when the NFC link is deactivated so the next tap starts clean. */
    fun reset() {
        applicationSelected = false
        selectedFile = null
        tnepState = Phase.NOT_STARTED
        writeBuffer = null
    }

    private fun handleSelect(apdu: ByteArray): ByteArray {
        val p1 = apdu[2].toInt() and 0xFF
        if (p1 == Nfc.SELECT_P1_APPLICATION) { // SELECT by AID → the NDEF application
            applicationSelected = true
            return sw(Nfc.SW_SUCCESS)
        }
        if (p1 == Nfc.SELECT_P1_FILE && apdu.size >= 7) { // SELECT by file id
            val fid = ((apdu[5].toInt() and 0xFF) shl 8) or (apdu[6].toInt() and 0xFF)
            selectedFile = when (fid) {
                Nfc.CC_FILE_ID -> capabilityContainer()
                Nfc.NDEF_FILE_ID -> ndefFileForSelect()
                else -> null
            }
            return sw(if (selectedFile != null) Nfc.SW_SUCCESS else Nfc.SW_FILE_NOT_FOUND)
        }
        return sw(Nfc.SW_FILE_NOT_FOUND)
    }

    private fun handleReadBinary(apdu: ByteArray): ByteArray {
        val file = selectedFile ?: return sw(Nfc.SW_FILE_NOT_FOUND)
        val offset = ((apdu[2].toInt() and 0xFF) shl 8) or (apdu[3].toInt() and 0xFF)
        val le = if (apdu.size >= 5) (apdu[4].toInt() and 0xFF).let { if (it == 0) 256 else it } else 0
        if (offset > file.size) return sw(Nfc.SW_WRONG_LENGTH)
        return file.copyOfRange(offset, minOf(offset + le, file.size)) + swBytes(Nfc.SW_SUCCESS)
    }

    /**
     * NFC Forum Type 4 Tag §7.5.5 NDEF Write Procedure: the reader writes NLEN=0, the message body at
     * offset ≥ 2, then the real NLEN (or merges all three into one command). A complete message is handed
     * to the TNEP state machine, whose response becomes the NDEF file for the reader to read back.
     */
    private suspend fun handleUpdateBinary(apdu: ByteArray): ByteArray {
        if (!negotiated) return sw(Nfc.SW_FILE_NOT_FOUND) // static handover is read-only
        val offset = ((apdu[2].toInt() and 0xFF) shl 8) or (apdu[3].toInt() and 0xFF)
        val lc = if (apdu.size >= 5) apdu[4].toInt() and 0xFF else 0
        val data = if (apdu.size >= 5 + lc) apdu.copyOfRange(5, 5 + lc) else ByteArray(0)
        if (offset == 0) {
            if (data.size == 2) {
                val nlen = ((data[0].toInt() and 0xFF) shl 8) or (data[1].toInt() and 0xFF)
                return if (nlen == 0) {
                    writeBuffer = ByteArrayBuilder() // begin a new NDEF write
                    sw(Nfc.SW_SUCCESS)
                } else {
                    val buf = writeBuffer ?: return sw(Nfc.SW_ERROR)
                    if (nlen != buf.size) return sw(Nfc.SW_ERROR)
                    writeBuffer = null
                    completeWrite(buf.toByteArray())
                }
            }
            // Merged single-command write: NLEN (2 bytes) + the whole NDEF message.
            if (data.size > 2 && writeBuffer == null) return completeWrite(data.copyOfRange(2, data.size))
            return sw(Nfc.SW_ERROR)
        }
        // Body chunk at offset ≥ 2, written sequentially after the NLEN=0 reset.
        val buf = writeBuffer ?: return sw(Nfc.SW_ERROR)
        if (offset - 2 != buf.size) return sw(Nfc.SW_ERROR)
        buf.append(data)
        return sw(Nfc.SW_SUCCESS)
    }

    /** Runs the TNEP state machine on a fully-received NDEF message and stages its response in the NDEF file. */
    private suspend fun completeWrite(message: ByteArray): ByteArray {
        val response = try {
            ndefTransact(message)
        } catch (e: Throwable) {
            return sw(Nfc.SW_ERROR)
        }
        selectedFile = withNlen(response)
        return sw(Nfc.SW_SUCCESS)
    }

    private suspend fun ndefTransact(message: ByteArray): ByteArray {
        val records = Ndef.decodeMessage(message)
        return when (tnepState) {
            Phase.EXPECT_SERVICE_SELECT -> {
                val name = records.firstNotNullOfOrNull { Tnep.parseServiceSelect(it) }
                    ?: throw IllegalStateException("expected a TNEP Service Select")
                if (name != Nfc.SERVICE_NAME_HANDOVER) throw IllegalStateException("unexpected TNEP service $name")
                tnepState = Phase.EXPECT_HANDOVER_REQUEST
                Ndef.encodeMessage(listOf(Tnep.tnepStatusRecord(0x00)))
            }
            Phase.EXPECT_HANDOVER_REQUEST -> {
                // The reader's Handover Request; hand the exact bytes to the caller, which returns the Handover Select.
                val hs = negotiatedHandoverSelect!!.invoke(message)
                tnepState = Phase.DONE
                hs
            }
            else -> throw IllegalStateException("no NDEF write expected in state $tnepState")
        }
    }

    private fun ndefFileForSelect(): ByteArray {
        if (!negotiated) return withNlen(staticHandoverSelect!!) // static: serve the Handover Select directly
        tnepState = Phase.EXPECT_SERVICE_SELECT // negotiated: advertise the Connection Handover service via TNEP
        return withNlen(Ndef.encodeMessage(listOf(Tnep.serviceParameterRecord())))
    }

    /** Capability Container: NDEF file E104, max 0x7FFF; write access granted only for negotiated handover. */
    private fun capabilityContainer(): ByteArray = byteArrayOf(
        0x00, 0x0F, 0x20, 0x7F, 0xFF.toByte(), 0x7F, 0xFF.toByte(),
        0x04, 0x06, 0xE1.toByte(), 0x04, 0x7F, 0xFF.toByte(), 0x00,
        if (negotiated) 0x00 else 0xFF.toByte(),
    )

    private fun withNlen(message: ByteArray): ByteArray =
        byteArrayOf((message.size shr 8).toByte(), (message.size and 0xFF).toByte()) + message

    private fun sw(status: Int): ByteArray = swBytes(status)
    private fun swBytes(status: Int): ByteArray = byteArrayOf((status shr 8).toByte(), (status and 0xFF).toByte())

    private class ByteArrayBuilder {
        private val out = java.io.ByteArrayOutputStream()
        val size: Int get() = out.size()
        fun append(bytes: ByteArray) = out.write(bytes)
        fun toByteArray(): ByteArray = out.toByteArray()
    }
}
