package com.hopae.eudi.wallet.cbor

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class DeterministicTest {

    private fun enc(v: Cbor, order: MapKeyOrder = MapKeyOrder.Bytewise8949): String =
        CborEncoder.encode(v, order).toHex()

    @Test
    fun rfc8949MapKeySortExample() {
        // RFC 8949 §4.2.1 example key order: 10, 100, -1, "z", "aa", [100], false
        val entries = listOf<Pair<Cbor, Cbor>>(
            Cbor.Text("aa") to Cbor.int(0),
            Cbor.Bool(false) to Cbor.int(0),
            Cbor.Array(listOf(Cbor.int(100))) to Cbor.int(0),
            Cbor.int(-1) to Cbor.int(0),
            Cbor.Text("z") to Cbor.int(0),
            Cbor.int(100) to Cbor.int(0),
            Cbor.int(10) to Cbor.int(0),
        )
        assertEquals(
            "a70a001864002000617a006261610081186400f400",
            enc(Cbor.CborMap(entries)),
        )
    }

    @Test
    fun shortestIntegerHeads() {
        assertEquals("00", enc(Cbor.int(0)))
        assertEquals("17", enc(Cbor.int(23)))
        assertEquals("1818", enc(Cbor.int(24)))
        assertEquals("18ff", enc(Cbor.int(255)))
        assertEquals("190100", enc(Cbor.int(256)))
        assertEquals("19ffff", enc(Cbor.int(65535)))
        assertEquals("1a00010000", enc(Cbor.int(65536)))
        assertEquals("1affffffff", enc(Cbor.int(4294967295)))
        assertEquals("1b0000000100000000", enc(Cbor.int(4294967296)))
        assertEquals("1bffffffffffffffff", enc(Cbor.UInt(ULong.MAX_VALUE)))
    }

    @Test
    fun negativeIntegers() {
        assertEquals("20", enc(Cbor.int(-1)))
        assertEquals("37", enc(Cbor.int(-24)))
        assertEquals("3818", enc(Cbor.int(-25)))
        assertEquals("38ff", enc(Cbor.int(-256)))
        assertEquals("390100", enc(Cbor.int(-257)))
        assertEquals("3bffffffffffffffff", enc(Cbor.NInt(ULong.MAX_VALUE))) // -2^64
    }

    @Test
    fun floatPreferredSerialization() {
        val cases = listOf(
            0.0 to "f90000",
            -0.0 to "f98000",
            1.0 to "f93c00",
            1.5 to "f93e00",
            65504.0 to "f97bff",
            5.960464477539063e-8 to "f90001",     // smallest subnormal half
            6.103515625e-5 to "f90400",           // smallest normal half
            100000.0 to "fa47c35000",
            3.4028234663852886e38 to "fa7f7fffff",
            1.1 to "fb3ff199999999999a",
            1.0e300 to "fb7e37e43c8800759c",
            -4.0 to "f9c400",
            Double.POSITIVE_INFINITY to "f97c00",
            Double.NEGATIVE_INFINITY to "f9fc00",
        )
        for ((d, hex) in cases) {
            assertEquals(hex, enc(Cbor.Fp.of(d)), "for $d")
        }
        assertEquals("f97e00", enc(Cbor.Fp.of(Double.NaN)), "NaN must canonicalize")
        assertEquals("f97e00", enc(Cbor.Fp(Double.fromBits(0x7FF8_0000_0000_0001L).toRawBits())), "NaN payload must canonicalize")
    }

    @Test
    fun strictRejectsIndefiniteLengths() {
        for (hex in listOf(
            "5f42010243030405ff",       // indefinite bytes
            "7f657374726561646d696e67ff", // indefinite text
            "9fff",                      // indefinite array
            "bf61610161629f0203ffff",    // indefinite map
        )) {
            assertFailsWith<CborDecodeException>(hex) { CborDecoder.decode(hex.hexToBytes(), strict = true) }
        }
    }

    @Test
    fun lenientDecodesIndefiniteLengths() {
        val v = CborDecoder.decode("9f018202039f0405ffff".hexToBytes(), strict = false)
        assertEquals(
            Cbor.Array(
                listOf(
                    Cbor.int(1),
                    Cbor.Array(listOf(Cbor.int(2), Cbor.int(3))),
                    Cbor.Array(listOf(Cbor.int(4), Cbor.int(5))),
                )
            ),
            v,
        )
    }

    @Test
    fun strictRejectsDuplicateMapKeys() {
        assertFailsWith<CborDecodeException> { CborDecoder.decode("a201000100".hexToBytes(), strict = true) }
    }

    @Test
    fun encoderRejectsDuplicateMapKeys() {
        assertFailsWith<IllegalArgumentException> {
            CborEncoder.encode(Cbor.CborMap(listOf(Cbor.int(1) to Cbor.int(0), Cbor.int(1) to Cbor.int(2))))
        }
    }

    @Test
    fun invalidTwoByteSimpleRejected() {
        assertFailsWith<CborDecodeException> { CborDecoder.decode("f814".hexToBytes()) } // simple(20) in f8 form
    }

    @Test
    fun trailingBytesRejected() {
        assertFailsWith<CborDecodeException> { CborDecoder.decode("0000".hexToBytes()) }
    }

    @Test
    fun invalidUtf8Rejected() {
        assertFailsWith<CborDecodeException> { CborDecoder.decode("62c328".hexToBytes()) }
    }

    @Test
    fun lengthFirstOrderOption() {
        // keys: -1 (0x20, len 1), 100 (0x1864, len 2), "a" (0x6161, len 2)
        val entries = listOf<Pair<Cbor, Cbor>>(
            Cbor.Text("a") to Cbor.int(0),
            Cbor.int(-1) to Cbor.int(0),
            Cbor.int(100) to Cbor.int(0),
        )
        // RFC 8949 bytewise: 0x1864 < 0x20 < 0x6161
        assertEquals("a3186400200061610 0".replace(" ", ""), enc(Cbor.CborMap(entries)))
        // RFC 7049 length-first: 0x20 < 0x1864 < 0x6161
        assertEquals("a3200018640061610 0".replace(" ", ""), enc(Cbor.CborMap(entries), MapKeyOrder.LengthFirst7049))
    }
}
