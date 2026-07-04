package com.hopae.eudi.wallet.cbor

import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.nio.charset.CharacterCodingException
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets

class CborDecodeException(message: String) : Exception(message)

/**
 * CBOR decoder (RFC 8949).
 *
 * [strict] = deterministic profile: rejects indefinite lengths and duplicate map keys.
 * Lenient mode accepts well-formed indefinite-length items (needed to consume third-party data
 * and the RFC 8949 Appendix A corpus).
 */
class CborDecoder private constructor(private val data: ByteArray, private val strict: Boolean) {

    private var pos = 0
    private var depth = 0

    companion object {
        private const val MAX_DEPTH = 512

        fun decode(data: ByteArray, strict: Boolean = true): Cbor {
            val d = CborDecoder(data, strict)
            val v = d.readValue()
            if (d.pos != data.size) throw CborDecodeException("trailing bytes after top-level item")
            return v
        }
    }

    private fun byte(): Int {
        if (pos >= data.size) throw CborDecodeException("unexpected end of input")
        return data[pos++].toInt() and 0xFF
    }

    private fun take(n: Int): ByteArray {
        if (n < 0 || pos + n > data.size) throw CborDecodeException("unexpected end of input")
        val r = data.copyOfRange(pos, pos + n)
        pos += n
        return r
    }

    private fun remaining(): ULong = (data.size - pos).toULong()

    private fun arg(info: Int): ULong = when {
        info < 24 -> info.toULong()
        info == 24 -> byte().toULong()
        info == 25 -> ((byte() shl 8) or byte()).toULong()
        info == 26 -> {
            var r = 0uL; repeat(4) { r = (r shl 8) or byte().toULong() }; r
        }
        info == 27 -> {
            var r = 0uL; repeat(8) { r = (r shl 8) or byte().toULong() }; r
        }
        else -> throw CborDecodeException("reserved additional info $info")
    }

    private fun eatBreak(): Boolean {
        if (pos < data.size && (data[pos].toInt() and 0xFF) == 0xFF) {
            pos++; return true
        }
        return false
    }

    private fun readValue(): Cbor {
        if (++depth > MAX_DEPTH) throw CborDecodeException("nesting too deep")
        try {
            val ib = byte()
            val major = ib ushr 5
            val info = ib and 0x1F
            return when (major) {
                0 -> Cbor.UInt(arg(info))
                1 -> Cbor.NInt(arg(info))
                2 -> Cbor.Bytes(readChunks(info, major = 2))
                3 -> Cbor.Text(decodeUtf8(readChunks(info, major = 3)))
                4 -> readArray(info)
                5 -> readMap(info)
                6 -> {
                    if (info == 31) throw CborDecodeException("tag with indefinite argument")
                    Cbor.Tagged(arg(info), readValue())
                }
                else -> readMajor7(info)
            }
        } finally {
            depth--
        }
    }

    private fun readChunks(info: Int, major: Int): ByteArray {
        if (info != 31) {
            val len = arg(info)
            if (len > remaining()) throw CborDecodeException("string length exceeds input")
            return take(len.toInt())
        }
        if (strict) throw CborDecodeException("indefinite length not allowed in deterministic profile")
        val out = ByteArrayOutputStream()
        while (!eatBreak()) {
            val ib = byte()
            val m = ib ushr 5
            val i = ib and 0x1F
            if (m != major || i == 31) throw CborDecodeException("invalid indefinite-length string chunk")
            val len = arg(i)
            if (len > remaining()) throw CborDecodeException("chunk length exceeds input")
            out.write(take(len.toInt()))
        }
        return out.toByteArray()
    }

    private fun readArray(info: Int): Cbor {
        if (info == 31) {
            if (strict) throw CborDecodeException("indefinite length not allowed in deterministic profile")
            val items = ArrayList<Cbor>()
            while (!eatBreak()) items.add(readValue())
            return Cbor.Array(items)
        }
        val count = arg(info)
        if (count > remaining()) throw CborDecodeException("array length exceeds input")
        val items = ArrayList<Cbor>(count.toInt())
        repeat(count.toInt()) { items.add(readValue()) }
        return Cbor.Array(items)
    }

    private fun readMap(info: Int): Cbor {
        val entries = ArrayList<Pair<Cbor, Cbor>>()
        val seen = if (strict) HashSet<String>() else null
        fun add(k: Cbor, v: Cbor) {
            if (seen != null) {
                val canonical = CborEncoder.encode(k).joinToString("") { "%02x".format(it) }
                if (!seen.add(canonical)) throw CborDecodeException("duplicate map key")
            }
            entries.add(k to v)
        }
        if (info == 31) {
            if (strict) throw CborDecodeException("indefinite length not allowed in deterministic profile")
            while (!eatBreak()) add(readValue(), readValue())
            return Cbor.CborMap(entries)
        }
        val count = arg(info)
        if (count > remaining()) throw CborDecodeException("map length exceeds input")
        repeat(count.toInt()) { add(readValue(), readValue()) }
        return Cbor.CborMap(entries)
    }

    private fun readMajor7(info: Int): Cbor = when (info) {
        in 0..19 -> Cbor.Simple(info.toUByte())
        20 -> Cbor.Bool(false)
        21 -> Cbor.Bool(true)
        22 -> Cbor.Null
        23 -> Cbor.Undefined
        24 -> {
            val s = byte()
            // values 0..19 have one-byte forms, 20..23 are bool/null/undefined: not well-formed here
            if (s < 24) throw CborDecodeException("invalid two-byte simple value $s")
            Cbor.Simple(s.toUByte())
        }
        25 -> {
            val h = (byte() shl 8) or byte()
            Cbor.Fp(Half.toDouble(h).toRawBits())
        }
        26 -> {
            var r = 0; repeat(4) { r = (r shl 8) or byte() }
            Cbor.Fp(Float.fromBits(r).toDouble().toRawBits())
        }
        27 -> {
            var r = 0L; repeat(8) { r = (r shl 8) or byte().toLong() }
            Cbor.Fp(r)
        }
        31 -> throw CborDecodeException("unexpected break")
        else -> throw CborDecodeException("reserved additional info $info for major 7")
    }

    private fun decodeUtf8(b: ByteArray): String {
        val decoder = StandardCharsets.UTF_8.newDecoder()
            .onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT)
        return try {
            decoder.decode(ByteBuffer.wrap(b)).toString()
        } catch (e: CharacterCodingException) {
            throw CborDecodeException("invalid UTF-8 in text string")
        }
    }
}
