package com.hopae.eudi.wallet.proximity

import java.io.ByteArrayOutputStream

/** One NDEF record (NFC Forum NDEF spec). [tnf] is the 3-bit Type Name Format; type/id/payload are raw bytes. */
class NdefRecord(val tnf: Int, val type: ByteArray, val id: ByteArray = ByteArray(0), val payload: ByteArray)

/**
 * Minimal NDEF message encoder/decoder — enough for ISO/IEC 18013-5 NFC static handover (a Handover Select
 * record, the DeviceEngagement record, and a BLE carrier-configuration record). No chunking.
 */
object Ndef {
    const val TNF_WELL_KNOWN = 0x01
    const val TNF_MIME_MEDIA = 0x02
    const val TNF_EXTERNAL = 0x04

    fun encodeMessage(records: List<NdefRecord>): ByteArray {
        val out = ByteArrayOutputStream()
        records.forEachIndexed { i, r -> out.write(encodeRecord(r, first = i == 0, last = i == records.size - 1)) }
        return out.toByteArray()
    }

    fun decodeMessage(bytes: ByteArray): List<NdefRecord> {
        val records = mutableListOf<NdefRecord>()
        var i = 0
        while (i < bytes.size) {
            val flags = bytes[i++].toInt() and 0xFF
            val tnf = flags and 0x07
            val sr = flags and 0x10 != 0
            val il = flags and 0x08 != 0
            val typeLen = bytes[i++].toInt() and 0xFF
            val payloadLen = if (sr) {
                bytes[i++].toInt() and 0xFF
            } else {
                val l = ((bytes[i].toInt() and 0xFF) shl 24) or ((bytes[i + 1].toInt() and 0xFF) shl 16) or
                    ((bytes[i + 2].toInt() and 0xFF) shl 8) or (bytes[i + 3].toInt() and 0xFF)
                i += 4; l
            }
            val idLen = if (il) bytes[i++].toInt() and 0xFF else 0
            val type = bytes.copyOfRange(i, i + typeLen); i += typeLen
            val id = bytes.copyOfRange(i, i + idLen); i += idLen
            val payload = bytes.copyOfRange(i, i + payloadLen); i += payloadLen
            records.add(NdefRecord(tnf, type, id, payload))
            if (flags and 0x40 != 0) break // ME (last record)
        }
        return records
    }

    private fun encodeRecord(r: NdefRecord, first: Boolean, last: Boolean): ByteArray {
        val sr = r.payload.size < 256
        val il = r.id.isNotEmpty()
        var flags = r.tnf
        if (first) flags = flags or 0x80 // MB
        if (last) flags = flags or 0x40 // ME
        if (sr) flags = flags or 0x10 // SR
        if (il) flags = flags or 0x08 // IL
        val out = ByteArrayOutputStream()
        out.write(flags)
        out.write(r.type.size)
        if (sr) {
            out.write(r.payload.size)
        } else {
            val n = r.payload.size
            out.write((n ushr 24) and 0xFF); out.write((n ushr 16) and 0xFF); out.write((n ushr 8) and 0xFF); out.write(n and 0xFF)
        }
        if (il) out.write(r.id.size)
        out.write(r.type)
        if (il) out.write(r.id)
        out.write(r.payload)
        return out.toByteArray()
    }
}
