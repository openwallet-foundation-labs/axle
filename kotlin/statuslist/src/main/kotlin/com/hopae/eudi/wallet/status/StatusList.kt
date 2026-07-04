package com.hopae.eudi.wallet.status

import com.hopae.eudi.wallet.sdjwt.Base64Url
import com.hopae.eudi.wallet.sdjwt.JsonValue
import com.hopae.eudi.wallet.sdjwt.Jws
import java.util.zip.Inflater

class StatusListException(message: String) : Exception(message)

/** A credential's reference into a status list (IETF Token Status List §5). */
class StatusReference(val index: Long, val uri: String) {
    companion object {
        /** Extracts `status.status_list = { idx, uri }` from a credential's claims (null if absent). */
        fun fromClaims(claims: JsonValue.Obj): StatusReference? {
            val statusList = ((claims["status"] as? JsonValue.Obj)?.get("status_list")) as? JsonValue.Obj ?: return null
            val idx = (statusList["idx"] as? JsonValue.NumInt)?.value ?: return null
            val uri = (statusList["uri"] as? JsonValue.Str)?.value ?: return null
            return StatusReference(idx, uri)
        }
    }
}

/** Status values (IETF Token Status List §7.1); higher values are issuer/application-defined. */
enum class CredentialStatus(val value: Int) {
    VALID(0x00),
    INVALID(0x01),
    SUSPENDED(0x02),
    UNKNOWN(-1);

    companion object {
        fun of(value: Int): CredentialStatus = entries.firstOrNull { it.value == value } ?: UNKNOWN
    }
}

/**
 * A decoded status list: a packed bit array of [bits]-bit entries (IETF Token Status List §4).
 * Within each byte the lowest-index entry occupies the least-significant bits.
 */
class StatusList(val bits: Int, private val unpacked: ByteArray) {

    init {
        if (bits != 1 && bits != 2 && bits != 4 && bits != 8) throw StatusListException("invalid bits per entry: $bits")
    }

    /** Number of addressable entries. */
    val size: Long get() = unpacked.size.toLong() * (8 / bits)

    fun rawStatusAt(index: Long): Int {
        if (index < 0 || index >= size) throw StatusListException("status index $index out of range (size $size)")
        val entriesPerByte = 8 / bits
        val byte = unpacked[(index / entriesPerByte).toInt()].toInt() and 0xFF
        val shift = (index % entriesPerByte).toInt() * bits
        val mask = (1 shl bits) - 1
        return (byte ushr shift) and mask
    }

    fun statusAt(index: Long): CredentialStatus = CredentialStatus.of(rawStatusAt(index))

    companion object {
        /** Parses a Status List Token JWS payload (`status_list = { bits, lst }`). */
        fun fromTokenPayload(payload: JsonValue.Obj): StatusList {
            val sl = payload["status_list"] as? JsonValue.Obj ?: throw StatusListException("missing status_list")
            val bits = (sl["bits"] as? JsonValue.NumInt)?.value?.toInt() ?: throw StatusListException("missing bits")
            val lst = (sl["lst"] as? JsonValue.Str)?.value ?: throw StatusListException("missing lst")
            return fromBitsAndCompressed(bits, Base64Url.decode(lst))
        }

        /** Builds a status list from `bits` and the zlib-compressed `lst` bytes (JWT or CWT). */
        fun fromBitsAndCompressed(bits: Int, compressedLst: ByteArray): StatusList =
            StatusList(bits, inflate(compressedLst))

        /** Parses + returns the status list carried by a `statuslist+jwt` (signature checked separately). */
        fun fromToken(jws: Jws): StatusList {
            val payload = JsonValue.parse(jws.payloadBytes.decodeToString()) as? JsonValue.Obj
                ?: throw StatusListException("status list token payload must be JSON")
            return fromTokenPayload(payload)
        }

        private fun inflate(compressed: ByteArray): ByteArray {
            val inflater = Inflater()
            inflater.setInput(compressed)
            val out = ByteArray(8192)
            val sb = ArrayList<Byte>()
            try {
                while (!inflater.finished()) {
                    val n = inflater.inflate(out)
                    if (n == 0 && inflater.needsInput()) break
                    for (i in 0 until n) sb.add(out[i])
                }
            } catch (e: Exception) {
                throw StatusListException("status list is not valid DEFLATE data: ${e.message}")
            } finally {
                inflater.end()
            }
            return sb.toByteArray()
        }
    }
}
