package com.hopae.eudi.wallet.cbor

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.io.File
import java.math.BigInteger
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.test.fail

/** Runs the official RFC 8949 Appendix A corpus (vectors/appendix_a.json from cbor/test-vectors). */
class AppendixATest {

    private fun vectorsFile(): File {
        var dir: File? = File(System.getProperty("user.dir")).absoluteFile
        while (dir != null) {
            val f = File(dir, "vectors/appendix_a.json")
            if (f.exists()) return f
            dir = dir.parentFile
        }
        fail("vectors/appendix_a.json not found above ${System.getProperty("user.dir")}")
    }

    @Test
    fun appendixA() {
        val vectors = Json.parseToJsonElement(vectorsFile().readText()).jsonArray
        var decoded = 0
        var roundtripped = 0
        var compared = 0
        val failures = mutableListOf<String>()

        for (entry in vectors) {
            val o = entry.jsonObject
            val hex = o["hex"]!!.jsonPrimitive.content
            try {
                val bytes = hex.hexToBytes()
                val v = CborDecoder.decode(bytes, strict = false)
                decoded++
                o["decoded"]?.let { expected ->
                    assertMatches(expected, v, hex)
                    compared++
                }
                if (o["roundtrip"]!!.jsonPrimitive.boolean) {
                    assertEquals(hex, CborEncoder.encode(v).toHex(), "roundtrip mismatch for $hex")
                    roundtripped++
                }
            } catch (e: AssertionError) {
                failures.add("$hex: ${e.message}")
            } catch (e: Exception) {
                failures.add("$hex: ${e::class.simpleName}: ${e.message}")
            }
        }

        println("appendix-a: total=${vectors.size} decoded=$decoded value-compared=$compared roundtripped=$roundtripped")
        if (failures.isNotEmpty()) fail("failures (${failures.size}):\n" + failures.joinToString("\n"))
        assertTrue(vectors.size > 70, "unexpectedly small corpus: ${vectors.size}")
    }

    private fun assertMatches(expected: JsonElement, actual: Cbor, ctx: String) {
        when (actual) {
            is Cbor.Tagged -> {
                val inner = actual.value
                when {
                    actual.tag == 2uL && inner is Cbor.Bytes ->
                        assertEquals(primitive(expected, ctx).content, BigInteger(1, inner.value).toString(), "bignum in $ctx")
                    actual.tag == 3uL && inner is Cbor.Bytes ->
                        assertEquals(
                            primitive(expected, ctx).content,
                            BigInteger(1, inner.value).negate().subtract(BigInteger.ONE).toString(),
                            "negative bignum in $ctx",
                        )
                    else -> assertMatches(expected, inner, ctx)
                }
            }
            is Cbor.UInt -> assertEquals(primitive(expected, ctx).content, actual.value.toString(), "uint in $ctx")
            is Cbor.NInt -> {
                val v = BigInteger(actual.n.toString()).negate().subtract(BigInteger.ONE)
                assertEquals(primitive(expected, ctx).content, v.toString(), "nint in $ctx")
            }
            is Cbor.Text -> {
                val p = primitive(expected, ctx)
                assertTrue(p.isString, "expected string for $ctx")
                assertEquals(p.content, actual.value, "text in $ctx")
            }
            is Cbor.Bool -> assertEquals(primitive(expected, ctx).content.toBooleanStrict(), actual.value, "bool in $ctx")
            Cbor.Null -> assertEquals(JsonNull, expected, "null in $ctx")
            is Cbor.Fp -> {
                val exp = primitive(expected, ctx).content.toDouble()
                assertEquals(exp.toRawBits(), actual.bits, "float in $ctx (expected $exp, got ${actual.value})")
            }
            is Cbor.Array -> {
                val arr = expected as? JsonArray ?: fail("expected array for $ctx")
                assertEquals(arr.size, actual.items.size, "array size in $ctx")
                arr.zip(actual.items).forEach { (e, c) -> assertMatches(e, c, ctx) }
            }
            is Cbor.CborMap -> {
                val obj = expected as? JsonObject ?: fail("expected object for $ctx")
                assertEquals(obj.size, actual.entries.size, "map size in $ctx")
                for ((k, v) in actual.entries) {
                    val ks = when (k) {
                        is Cbor.Text -> k.value
                        is Cbor.UInt -> k.value.toString()
                        is Cbor.NInt -> BigInteger(k.n.toString()).negate().subtract(BigInteger.ONE).toString()
                        else -> fail("unexpected map key type in $ctx")
                    }
                    assertMatches(obj[ks] ?: fail("missing key '$ks' in expected object for $ctx"), v, ctx)
                }
            }
            else -> fail("no decoded-comparison rule for $actual in $ctx")
        }
    }

    private fun primitive(e: JsonElement, ctx: String): JsonPrimitive =
        e as? JsonPrimitive ?: fail("expected primitive for $ctx, got $e")
}

internal fun String.hexToBytes(): ByteArray {
    require(length % 2 == 0)
    return ByteArray(length / 2) { ((this[it * 2].digitToInt(16) shl 4) or this[it * 2 + 1].digitToInt(16)).toByte() }
}

internal fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }
