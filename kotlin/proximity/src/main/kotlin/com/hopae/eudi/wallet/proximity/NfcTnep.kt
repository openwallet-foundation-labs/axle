package com.hopae.eudi.wallet.proximity

/** NFC Forum Type-4 Tag + ISO/IEC 18013-5 constants shared by the holder ([NfcEngagementProcessor]) and reader ([MdocNfcHandover]). */
object Nfc {
    /** ISO 18013-5 §8.3.3.1.2 NDEF application AID (`D2760000850101`). */
    val NDEF_APPLICATION_ID = byteArrayOf(0xD2.toByte(), 0x76, 0x00, 0x00, 0x85.toByte(), 0x01, 0x01)
    const val CC_FILE_ID = 0xE103
    const val NDEF_FILE_ID = 0xE104

    const val INS_SELECT = 0xA4
    const val INS_READ_BINARY = 0xB0
    const val INS_UPDATE_BINARY = 0xD6
    const val SELECT_P1_APPLICATION = 0x04
    const val SELECT_P1_FILE = 0x00

    const val SW_SUCCESS = 0x9000
    const val SW_FILE_NOT_FOUND = 0x6A82
    const val SW_WRONG_LENGTH = 0x6700
    const val SW_INS_NOT_SUPPORTED = 0x6D00
    const val SW_ERROR = 0x6F00

    /** NFC Forum TNEP service that carries Connection Handover (negotiated handover, ISO 18013-5 §8.2.2.1). */
    const val SERVICE_NAME_HANDOVER = "urn:nfc:sn:handover"
}

/** A parsed NFC Forum TNEP Service Parameter record — advertised by the mdoc when it offers negotiated handover. */
class ServiceParameter(val serviceNameUri: String, val wtInt: Int, val nWait: Int)

/**
 * NFC Forum **Tag NDEF Exchange Protocol** (TNEP) records used by ISO/IEC 18013-5 negotiated handover: the mdoc
 * advertises a [serviceParameterRecord] for the Connection Handover service, the reader answers with a
 * [serviceSelectRecord], the mdoc confirms with a [tnepStatusRecord], and the Handover Request / Select messages
 * are then exchanged over the same NDEF file. Record type names per NFC Forum RTD (`Tp` / `Ts` / `Te`).
 */
object Tnep {
    private val RTD_SERVICE_PARAMETER = "Tp".toByteArray()
    private val RTD_SERVICE_SELECT = "Ts".toByteArray()
    private val RTD_TNEP_STATUS = "Te".toByteArray()
    private const val TNEP_VERSION = 0x10

    /** The Service Parameter record advertising the Connection Handover service (TNEP single-response mode). */
    fun serviceParameterRecord(wtInt: Int = 0, nWait: Int = 15, maxNdefSize: Int = 0xFFFF): NdefRecord {
        val name = Nfc.SERVICE_NAME_HANDOVER.toByteArray()
        val payload = byteArrayOf(
            TNEP_VERSION.toByte(), name.size.toByte(),
        ) + name + byteArrayOf(
            0x00, // TNEP communication mode: single response
            wtInt.toByte(), nWait.toByte(),
            (maxNdefSize shr 8).toByte(), (maxNdefSize and 0xFF).toByte(),
        )
        return NdefRecord(Ndef.TNF_WELL_KNOWN, RTD_SERVICE_PARAMETER, payload = payload)
    }

    fun parseServiceParameter(record: NdefRecord): ServiceParameter? {
        if (record.tnf != Ndef.TNF_WELL_KNOWN || !record.type.contentEquals(RTD_SERVICE_PARAMETER)) return null
        val p = record.payload
        if (p.size < 2) return null
        val nameLen = p[1].toInt() and 0xFF
        if (p.size != nameLen + 7) return null
        val name = String(p.copyOfRange(2, 2 + nameLen))
        return ServiceParameter(name, wtInt = p[3 + nameLen].toInt() and 0xFF, nWait = p[4 + nameLen].toInt() and 0xFF)
    }

    /** The reader's Service Select record choosing [serviceName] (the Connection Handover service). */
    fun serviceSelectRecord(serviceName: String = Nfc.SERVICE_NAME_HANDOVER): NdefRecord {
        val name = serviceName.toByteArray()
        return NdefRecord(Ndef.TNF_WELL_KNOWN, RTD_SERVICE_SELECT, payload = byteArrayOf(name.size.toByte()) + name)
    }

    fun parseServiceSelect(record: NdefRecord): String? {
        if (record.tnf != Ndef.TNF_WELL_KNOWN || !record.type.contentEquals(RTD_SERVICE_SELECT)) return null
        val p = record.payload
        if (p.isEmpty()) return null
        val nameLen = p[0].toInt() and 0xFF
        if (p.size != nameLen + 1) return null
        return String(p.copyOfRange(1, 1 + nameLen))
    }

    /** The mdoc's TNEP Status record ([status] 0x00 = success). */
    fun tnepStatusRecord(status: Int = 0x00): NdefRecord =
        NdefRecord(Ndef.TNF_WELL_KNOWN, RTD_TNEP_STATUS, payload = byteArrayOf(status.toByte()))

    fun parseTnepStatus(record: NdefRecord): Int? {
        if (record.tnf != Ndef.TNF_WELL_KNOWN || !record.type.contentEquals(RTD_TNEP_STATUS)) return null
        return if (record.payload.size == 1) record.payload[0].toInt() and 0xFF else null
    }
}
