package com.hopae.eudi.wallet.cbor

/** IEEE 754 half-precision (binary16) helpers for CBOR preferred float serialization. */
internal object Half {

    /** Half bits -> double (exact; subnormals, ±0, ±inf, NaN). */
    fun toDouble(h: Int): Double {
        val neg = (h and 0x8000) != 0
        val exp = (h ushr 10) and 0x1F
        val mant = h and 0x3FF
        val mag = when (exp) {
            0 -> Math.scalb(mant.toDouble(), -24)
            0x1F -> if (mant == 0) Double.POSITIVE_INFINITY else Double.NaN
            else -> Math.scalb((0x400 or mant).toDouble(), exp - 25)
        }
        return if (neg) -mag else mag
    }

    /**
     * Returns the half bits if [d] is exactly representable as binary16, else null.
     * NaN is excluded (the encoder canonicalizes NaN to 0x7e00 separately).
     */
    fun exactBitsOf(d: Double): Int? {
        val bits = d.toRawBits()
        val sign = ((bits ushr 48) and 0x8000L).toInt()
        if (d.isNaN()) return null
        if (d.isInfinite()) return sign or 0x7C00
        if (d == 0.0) return if (bits == 0L) 0x0000 else 0x8000
        val exp = ((bits ushr 52) and 0x7FFL).toInt() - 1023
        val mant = bits and 0xF_FFFF_FFFF_FFFFL
        if (exp in -14..15) {
            // normal half: needs a 10-bit mantissa
            if (mant and ((1L shl 42) - 1) != 0L) return null
            return sign or ((exp + 15) shl 10) or (mant ushr 42).toInt()
        }
        if (exp in -24..-15) {
            // subnormal half: d = ±k * 2^-24, 1 <= k <= 1023
            val shift = 52 - (exp + 24)
            val full = (1L shl 52) or mant
            if (full and ((1L shl shift) - 1) != 0L) return null
            val k = full ushr shift
            if (k in 1..0x3FF) return sign or k.toInt()
        }
        return null
    }
}
