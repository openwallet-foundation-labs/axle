package com.hopae.eudi.wallet.cbor.cose

import com.hopae.eudi.wallet.cbor.hexToBytes
import com.hopae.eudi.wallet.cbor.toHex
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.io.File
import java.math.BigInteger
import java.security.KeyFactory
import java.security.Signature
import java.security.spec.ECPrivateKeySpec
import java.util.Base64
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlin.test.fail

/** Runs the official cose-wg/Examples sign1-tests corpus (vectors/cose/). */
class CoseSign1Test {

    private fun vectorsDir(): File {
        var dir: File? = File(System.getProperty("user.dir")).absoluteFile
        while (dir != null) {
            val f = File(dir, "vectors/cose")
            if (f.isDirectory) return f
            dir = dir.parentFile
        }
        fail("vectors/cose not found above ${System.getProperty("user.dir")}")
    }

    private fun b64url(s: String): ByteArray = Base64.getUrlDecoder().decode(s)

    private class Vector(file: File) {
        val json = Json.parseToJsonElement(file.readText()).jsonObject
        val sign0 = json["input"]!!.jsonObject["sign0"]!!.jsonObject
        val key = sign0["key"]!!.jsonObject
        val x = Base64.getUrlDecoder().decode(key["x"]!!.jsonPrimitive.content)
        val y = Base64.getUrlDecoder().decode(key["y"]!!.jsonPrimitive.content)
        val d = Base64.getUrlDecoder().decode(key["d"]!!.jsonPrimitive.content)
        val external = sign0["external"]?.jsonPrimitive?.content?.hexToBytes() ?: ByteArray(0)
        val cbor = json["output"]!!.jsonObject["cbor"]!!.jsonPrimitive.content.lowercase()
        val toBeSign = json["intermediates"]?.jsonObject?.get("ToBeSign_hex")?.jsonPrimitive?.content?.lowercase()
        val publicKey = EcPublicKey(EcCurve.P256, x, y)
    }

    @Test
    fun passVectors() {
        for (name in listOf("sign-pass-01", "sign-pass-02", "sign-pass-03")) {
            val v = Vector(File(vectorsDir(), "$name.json"))
            val bytes = v.cbor.hexToBytes()
            val tagged = (bytes[0].toInt() and 0xFF) == 0xD2

            val s1 = CoseSign1.decode(bytes)

            // 1. Sig_structure must match the official intermediate byte-for-byte
            val toBeSigned = CoseSign1.sigStructure(s1.protectedBytes, v.external, s1.payload!!)
            assertEquals(v.toBeSign, toBeSigned.toHex(), "$name: Sig_structure")

            // 2. official signature verifies
            assertTrue(s1.verify(v.publicKey, v.external), "$name: verify")

            // 3. re-encode is byte-identical (vectors are deterministically encoded)
            assertEquals(v.cbor, s1.encode(tagged).toHex(), "$name: re-encode")

            // 4. tampered payload fails
            val tampered = s1.payload!!.clone().also { it[0] = (it[0] + 1).toByte() }
            assertFalse(
                CoseSign1(s1.protectedBytes, s1.unprotected, tampered, s1.signature).verify(v.publicKey, v.external),
                "$name: tamper",
            )

            // 5. our own signature (same headers/payload, software key) verifies
            val signed = runBlocking {
                CoseSign1.sign(
                    protected = s1.protected,
                    unprotected = s1.unprotected,
                    payload = s1.payload,
                    externalAad = v.external,
                    signer = SoftwareCoseSigner(v.d, EcCurve.P256, CoseAlgorithm.ES256),
                )
            }
            assertTrue(signed.verify(v.publicKey, v.external), "$name: sign roundtrip")
        }
    }

    @Test
    fun failVectorChangedContent() {
        val v = Vector(File(vectorsDir(), "sign-fail-02.json"))
        val s1 = CoseSign1.decode(v.cbor.hexToBytes())
        assertFalse(s1.verify(v.publicKey, v.external))
    }

    @Test
    fun headerAccessors() {
        val v = Vector(File(vectorsDir(), "sign-pass-01.json"))
        val s1 = CoseSign1.decode(v.cbor.hexToBytes())
        // pass-01: protected is h'A0' (empty map), alg + kid live in unprotected
        assertTrue(s1.protected.isEmpty)
        assertEquals(CoseAlgorithm.ES256, s1.unprotected.algorithm)
        assertContentEquals("11".encodeToByteArray(), s1.unprotected.kid)
        assertEquals(CoseAlgorithm.ES256, s1.algorithm)
    }

    @Test
    fun derRawConversionRoundtrip() {
        val raw = ByteArray(64) { (it + 1).toByte() }
        assertContentEquals(raw, Der.derSignatureToRaw(Der.rawSignatureToDer(raw), 32))
    }
}

/** Test-only software signer; the real one is the SecureArea adapter (wallet-api port). */
private class SoftwareCoseSigner(
    d: ByteArray,
    private val curve: EcCurve,
    override val algorithm: CoseAlgorithm,
) : CoseSigner {
    private val privateKey = KeyFactory.getInstance("EC")
        .generatePrivate(ECPrivateKeySpec(BigInteger(1, d), Ecdsa.parameterSpec(curve)))

    override suspend fun sign(toBeSigned: ByteArray): ByteArray =
        Signature.getInstance(algorithm.jcaName).run {
            initSign(privateKey)
            update(toBeSigned)
            Der.derSignatureToRaw(sign(), curve.coordinateSize)
        }
}
