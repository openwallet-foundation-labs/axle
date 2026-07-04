package com.hopae.eudi.wallet.cbor

import java.io.ByteArrayOutputStream

/**
 * Map key ordering profile.
 *
 * [Bytewise8949] is the RFC 8949 §4.2.1 core deterministic order (default).
 * [LengthFirst7049] is the legacy RFC 7049 §3.9 canonical order (length, then bytewise) —
 * kept selectable because ISO 18013-5 artifacts in the wild differ; interop to be pinned in M4.
 */
enum class MapKeyOrder { Bytewise8949, LengthFirst7049 }

object CborEncoder {

    fun encode(value: Cbor, mapOrder: MapKeyOrder = MapKeyOrder.Bytewise8949): ByteArray {
        val out = ByteArrayOutputStream()
        writeValue(value, out, mapOrder)
        return out.toByteArray()
    }

    private fun head(out: ByteArrayOutputStream, major: Int, arg: ULong) {
        val mt = major shl 5
        when {
            arg < 24u -> out.write(mt or arg.toInt())
            arg <= 0xFFu -> {
                out.write(mt or 24); out.write(arg.toInt())
            }
            arg <= 0xFFFFu -> {
                out.write(mt or 25); out.write(((arg shr 8) and 0xFFu).toInt()); out.write((arg and 0xFFu).toInt())
            }
            arg <= 0xFFFF_FFFFu -> {
                out.write(mt or 26)
                for (s in 24 downTo 0 step 8) out.write(((arg shr s) and 0xFFu).toInt())
            }
            else -> {
                out.write(mt or 27)
                for (s in 56 downTo 0 step 8) out.write(((arg shr s) and 0xFFu).toInt())
            }
        }
    }

    private fun writeValue(v: Cbor, out: ByteArrayOutputStream, order: MapKeyOrder) {
        when (v) {
            is Cbor.UInt -> head(out, 0, v.value)
            is Cbor.NInt -> head(out, 1, v.n)
            is Cbor.Bytes -> {
                head(out, 2, v.value.size.toULong()); out.write(v.value)
            }
            is Cbor.Text -> {
                val b = v.value.encodeToByteArray()
                head(out, 3, b.size.toULong()); out.write(b)
            }
            is Cbor.Array -> {
                head(out, 4, v.items.size.toULong())
                v.items.forEach { writeValue(it, out, order) }
            }
            is Cbor.CborMap -> writeMap(v, out, order)
            is Cbor.Tagged -> {
                head(out, 6, v.tag); writeValue(v.value, out, order)
            }
            is Cbor.Bool -> out.write(if (v.value) 0xF5 else 0xF4)
            Cbor.Null -> out.write(0xF6)
            Cbor.Undefined -> out.write(0xF7)
            is Cbor.Simple -> writeSimple(v.value, out)
            is Cbor.Fp -> writeFloat(v, out)
        }
    }

    private fun writeSimple(value: UByte, out: ByteArrayOutputStream) {
        val i = value.toInt()
        require(i !in 20..23) { "simple($i) has a dedicated encoding (bool/null/undefined)" }
        if (i < 20) out.write(0xE0 or i) else {
            out.write(0xF8); out.write(i)
        }
    }

    private fun writeFloat(fp: Cbor.Fp, out: ByteArrayOutputStream) {
        val d = fp.value
        if (d.isNaN()) { // canonical NaN
            out.write(0xF9); out.write(0x7E); out.write(0x00); return
        }
        val h = Half.exactBitsOf(d)
        if (h != null) {
            out.write(0xF9); out.write((h ushr 8) and 0xFF); out.write(h and 0xFF); return
        }
        val f = d.toFloat()
        if (f.toDouble().toRawBits() == fp.bits) {
            out.write(0xFA)
            val fb = f.toRawBits()
            for (s in 24 downTo 0 step 8) out.write((fb ushr s) and 0xFF)
        } else {
            out.write(0xFB)
            for (s in 56 downTo 0 step 8) out.write(((fp.bits ushr s) and 0xFF).toInt())
        }
    }

    private fun writeMap(m: Cbor.CborMap, out: ByteArrayOutputStream, order: MapKeyOrder) {
        head(out, 5, m.entries.size.toULong())
        val encoded = m.entries.map { (k, v) -> Pair(encode(k, order), v) }
        val sorted = encoded.sortedWith { a, b -> compareKeys(a.first, b.first, order) }
        for (i in 1 until sorted.size) {
            require(!sorted[i - 1].first.contentEquals(sorted[i].first)) { "duplicate map key" }
        }
        sorted.forEach { (kb, v) ->
            out.write(kb); writeValue(v, out, order)
        }
    }

    private fun compareKeys(a: ByteArray, b: ByteArray, order: MapKeyOrder): Int {
        if (order == MapKeyOrder.LengthFirst7049 && a.size != b.size) return a.size - b.size
        val n = minOf(a.size, b.size)
        for (i in 0 until n) {
            val c = (a[i].toInt() and 0xFF) - (b[i].toInt() and 0xFF)
            if (c != 0) return c
        }
        return a.size - b.size
    }
}
