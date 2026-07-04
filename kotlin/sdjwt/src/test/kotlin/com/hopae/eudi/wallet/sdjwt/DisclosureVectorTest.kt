package com.hopae.eudi.wallet.sdjwt

import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.test.fail

/** RFC 9901 example disclosures, extracted from the RFC text and self-verified at extraction time. */
class DisclosureVectorTest {

    private fun vectorsFile(): File {
        var dir: File? = File(System.getProperty("user.dir")).absoluteFile
        while (dir != null) {
            val f = File(dir, "vectors/sdjwt/rfc9901-disclosures.json")
            if (f.exists()) return f
            dir = dir.parentFile
        }
        fail("vectors/sdjwt/rfc9901-disclosures.json not found")
    }

    @Test
    fun rfc9901Disclosures() {
        val root = JsonValue.parse(vectorsFile().readText()) as JsonValue.Obj
        val vectors = root["vectors"] as JsonValue.Arr
        assertTrue(vectors.items.size > 50, "unexpectedly small corpus: ${vectors.items.size}")

        for (entry in vectors.items) {
            val o = entry as JsonValue.Obj
            val digest = (o["digest"] as JsonValue.Str).value
            val encoded = (o["disclosure"] as JsonValue.Str).value
            val contents = (o["contents"] as JsonValue.Str).value

            val disclosure = Disclosure.parse(encoded)
            assertEquals(digest, disclosure.digest, "digest mismatch for $encoded")

            // cross-check parsed fields against the RFC's own contents JSON
            val arr = JsonValue.parse(contents) as JsonValue.Arr
            assertEquals((arr.items[0] as JsonValue.Str).value, disclosure.salt)
            when (arr.items.size) {
                2 -> {
                    assertEquals(null, disclosure.claimName)
                    assertEquals(arr.items[1], disclosure.value)
                }
                3 -> {
                    assertEquals((arr.items[1] as JsonValue.Str).value, disclosure.claimName)
                    assertEquals(arr.items[2], disclosure.value)
                }
                else -> fail("unexpected contents arity")
            }
        }
    }

    @Test
    fun encodeParseRoundtrip() {
        val d = Disclosure.objectProperty("salt-123", "given_name", JsonValue.Str("John"))
        val parsed = Disclosure.parse(d.encoded)
        assertEquals(d.salt, parsed.salt)
        assertEquals(d.claimName, parsed.claimName)
        assertEquals(d.value, parsed.value)
        assertEquals(d.digest, parsed.digest)
    }
}
