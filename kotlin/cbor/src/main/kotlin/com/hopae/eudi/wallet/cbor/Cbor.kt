package com.hopae.eudi.wallet.cbor

/**
 * CBOR data model (RFC 8949).
 *
 * Deterministic encoding follows the Core Deterministic Encoding Requirements (RFC 8949 §4.2.1):
 * shortest-form heads, definite lengths only, bytewise-lexicographic map key order,
 * preferred (shortest exact) float serialization, canonical NaN (0x7e00).
 */
sealed class Cbor {

    /** Major type 0: unsigned integer 0..2^64-1. */
    data class UInt(val value: ULong) : Cbor()

    /** Major type 1: negative integer; represents -1 - [n], down to -2^64. */
    data class NInt(val n: ULong) : Cbor()

    /** Major type 2: byte string. */
    class Bytes(val value: ByteArray) : Cbor() {
        override fun equals(other: Any?): Boolean = other is Bytes && value.contentEquals(other.value)
        override fun hashCode(): Int = value.contentHashCode()
        override fun toString(): String = "Bytes(${value.joinToString("") { "%02x".format(it) }})"
    }

    /** Major type 3: text string (UTF-8). */
    data class Text(val value: String) : Cbor()

    /** Major type 4: array. */
    data class Array(val items: List<Cbor>) : Cbor()

    /** Major type 5: map. Entry order is preserved on decode; deterministic encoding sorts by key bytes. */
    data class CborMap(val entries: List<Pair<Cbor, Cbor>>) : Cbor()

    /** Major type 6: tagged value. */
    data class Tagged(val tag: ULong, val value: Cbor) : Cbor()

    /** Major type 7: simple value other than bool/null/undefined (0..19, 32..255). */
    data class Simple(val value: UByte) : Cbor()

    data class Bool(val value: Boolean) : Cbor()

    object Null : Cbor() {
        override fun toString(): String = "Null"
    }

    object Undefined : Cbor() {
        override fun toString(): String = "Undefined"
    }

    /** Major type 7: float. Raw IEEE 754 double bits are kept so -0.0 and NaN compare exactly. */
    data class Fp(val bits: Long) : Cbor() {
        val value: Double get() = Double.fromBits(bits)
        override fun toString(): String = "Fp($value)"

        companion object {
            fun of(d: Double): Fp = Fp(d.toRawBits())
        }
    }

    companion object {
        /** Convenience: signed integer to UInt/NInt. */
        fun int(v: Long): Cbor = if (v >= 0) UInt(v.toULong()) else NInt(v.inv().toULong())
    }
}
