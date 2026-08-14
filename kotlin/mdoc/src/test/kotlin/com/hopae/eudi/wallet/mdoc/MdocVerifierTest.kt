package com.hopae.eudi.wallet.mdoc

import com.hopae.eudi.wallet.cbor.Cbor
import com.hopae.eudi.wallet.cbor.cose.EcPublicKey
import com.hopae.eudi.wallet.spi.KeySpec
import com.hopae.eudi.wallet.spi.SigningAlgorithm
import com.hopae.eudi.wallet.testkit.SoftwareSecureArea
import kotlinx.coroutines.runBlocking
import java.time.Instant
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class MdocVerifierTest {

    private val docType = "org.iso.18013.5.1.mDL"
    private val namespace = "org.iso.18013.5.1"
    private val now = Instant.parse("2026-01-01T00:00:00Z")

    private class TestTrust(
        val expected: EcPublicKey,
        /** DS certificate window for §9.3.1 step 5; null keeps the check out of the way of other cases. */
        val notBefore: Instant? = null,
        val notAfter: Instant? = null,
    ) : MdocIssuerTrust {
        // Unit-level: return the known issuer key (chain validation is covered by the trust module).
        override suspend fun issuerKey(x5chain: List<ByteArray>): MdocIssuerKey =
            MdocIssuerKey(expected, notBefore, notAfter)
    }

    private fun issued(area: SoftwareSecureArea, issuerKey: com.hopae.eudi.wallet.spi.KeyInfo, deviceKey: EcPublicKey,
                       validUntil: Instant = Instant.parse("2027-01-01T00:00:00Z"),
                       digestAlgorithm: String = "SHA-256"): ByteArray = runBlocking {
        MdocTestIssuer.issue(
            area = area, issuerKey = issuerKey, deviceKey = deviceKey,
            docType = docType, namespace = namespace,
            elements = listOf(
                "family_name" to Cbor.Text("Han"),
                "given_name" to Cbor.Text("Jongho"),
                "age_over_18" to Cbor.Bool(true),
            ),
            x5chain = listOf(byteArrayOf(0x30, 0x01, 0x02)), // placeholder DER; resolver returns the known key
            signed = Instant.parse("2026-01-01T00:00:00Z"),
            validFrom = Instant.parse("2026-01-01T00:00:00Z"),
            validUntil = validUntil,
            digestAlgorithm = digestAlgorithm,
        )
    }

    @Test
    fun parseRoundtrip() {
        val area = SoftwareSecureArea()
        val issuerKey = runBlocking { area.createKey(KeySpec(secureArea = area.id, algorithm = SigningAlgorithm.ES256)) }
        val deviceKey = runBlocking { area.createKey(KeySpec(secureArea = area.id, algorithm = SigningAlgorithm.ES256)) }.publicKey
        val bytes = issued(area, issuerKey, deviceKey)

        val parsed = IssuerSigned.decode(bytes)
        assertEquals(3, parsed.nameSpaces[namespace]!!.size)
        assertEquals("family_name", parsed.nameSpaces[namespace]!![0].item.elementIdentifier)
        assertContentEquals(byteArrayOf(0x30, 0x01, 0x02), parsed.issuerCertChain!!.first())
    }

    @Test
    fun verifiesAndDisclosesElements() = runBlocking {
        val area = SoftwareSecureArea()
        val issuerKey = area.createKey(KeySpec(secureArea = area.id, algorithm = SigningAlgorithm.ES256))
        val deviceKey = area.createKey(KeySpec(secureArea = area.id, algorithm = SigningAlgorithm.ES256)).publicKey
        val bytes = issued(area, issuerKey, deviceKey)

        val verified = MdocVerifier(TestTrust(issuerKey.publicKey), now = { now }).verify(IssuerSigned.decode(bytes))
        assertEquals(docType, verified.docType)
        assertEquals(Cbor.Text("Han"), verified.elements[namespace]!!["family_name"])
        assertEquals(Cbor.Text("Jongho"), verified.elements[namespace]!!["given_name"])
        assertEquals(Cbor.Bool(true), verified.elements[namespace]!!["age_over_18"])
        assertContentEquals(deviceKey.x, verified.deviceKey.x) // holder binding preserved
    }

    @Test
    fun verifiesSha384AndSha512Digests() = runBlocking {
        // ISO 18013-5 §9.1.2.5: readers must support SHA-384 and SHA-512, not only SHA-256.
        for (alg in listOf("SHA-384", "SHA-512")) {
            val area = SoftwareSecureArea()
            val issuerKey = area.createKey(KeySpec(secureArea = area.id, algorithm = SigningAlgorithm.ES256))
            val deviceKey = area.createKey(KeySpec(secureArea = area.id, algorithm = SigningAlgorithm.ES256)).publicKey
            val bytes = issued(area, issuerKey, deviceKey, digestAlgorithm = alg)

            val verified = MdocVerifier(TestTrust(issuerKey.publicKey), now = { now }).verify(IssuerSigned.decode(bytes))
            assertEquals(Cbor.Text("Han"), verified.elements[namespace]!!["family_name"], "$alg digests verify")
            // a tampered element still fails under the stronger digest
            val idx = bytes.indexOf("Jongho".encodeToByteArray()); bytes[idx] = 'X'.code.toByte()
            assertFailsWith<MdocException>("tamper must fail under $alg") {
                MdocVerifier(TestTrust(issuerKey.publicKey), now = { now }).verify(IssuerSigned.decode(bytes))
            }
        }
    }

    @Test
    fun unsupportedDigestAlgorithmRejected(): Unit = runBlocking {
        val area = SoftwareSecureArea()
        val issuerKey = area.createKey(KeySpec(secureArea = area.id, algorithm = SigningAlgorithm.ES256))
        val deviceKey = area.createKey(KeySpec(secureArea = area.id, algorithm = SigningAlgorithm.ES256)).publicKey
        val bytes = issued(area, issuerKey, deviceKey, digestAlgorithm = "SHA-1")

        assertFailsWith<MdocException> {
            MdocVerifier(TestTrust(issuerKey.publicKey), now = { now }).verify(IssuerSigned.decode(bytes))
        }
    }

    @Test
    fun wrongIssuerKeyRejected(): Unit = runBlocking {
        val area = SoftwareSecureArea()
        val issuerKey = area.createKey(KeySpec(secureArea = area.id, algorithm = SigningAlgorithm.ES256))
        val wrongKey = area.createKey(KeySpec(secureArea = area.id, algorithm = SigningAlgorithm.ES256))
        val deviceKey = area.createKey(KeySpec(secureArea = area.id, algorithm = SigningAlgorithm.ES256)).publicKey
        val bytes = issued(area, issuerKey, deviceKey)

        assertFailsWith<MdocException> {
            MdocVerifier(TestTrust(wrongKey.publicKey), now = { now }).verify(IssuerSigned.decode(bytes))
        }
    }

    @Test
    fun tamperedElementRejected(): Unit = runBlocking {
        val area = SoftwareSecureArea()
        val issuerKey = area.createKey(KeySpec(secureArea = area.id, algorithm = SigningAlgorithm.ES256))
        val deviceKey = area.createKey(KeySpec(secureArea = area.id, algorithm = SigningAlgorithm.ES256)).publicKey
        val bytes = issued(area, issuerKey, deviceKey)

        // flip a byte inside the nameSpaces item so its digest no longer matches the MSO
        val idx = bytes.indexOf("Jongho".encodeToByteArray())
        bytes[idx] = 'X'.code.toByte()
        assertFailsWith<MdocException> {
            MdocVerifier(TestTrust(issuerKey.publicKey), now = { now }).verify(IssuerSigned.decode(bytes))
        }
    }

    @Test
    fun expiredMdocRejected(): Unit = runBlocking {
        val area = SoftwareSecureArea()
        val issuerKey = area.createKey(KeySpec(secureArea = area.id, algorithm = SigningAlgorithm.ES256))
        val deviceKey = area.createKey(KeySpec(secureArea = area.id, algorithm = SigningAlgorithm.ES256)).publicKey
        val bytes = issued(area, issuerKey, deviceKey, validUntil = Instant.parse("2026-06-01T00:00:00Z"))

        assertFailsWith<MdocException> {
            MdocVerifier(TestTrust(issuerKey.publicKey), now = { Instant.parse("2026-12-01T00:00:00Z") })
                .verify(IssuerSigned.decode(bytes))
        }
    }

    /**
     * ISO 18013-5 §9.3.1 step 5, first bullet: "the 'signed' date is within the validity period of the
     * certificate in the MSO header". The MSO here is signed 2026-01-01.
     */
    @Test
    fun signedBeforeTheDocumentSignerCertificateRejected(): Unit = runBlocking {
        val area = SoftwareSecureArea()
        val issuerKey = area.createKey(KeySpec(secureArea = area.id, algorithm = SigningAlgorithm.ES256))
        val deviceKey = area.createKey(KeySpec(secureArea = area.id, algorithm = SigningAlgorithm.ES256)).publicKey
        val bytes = issued(area, issuerKey, deviceKey)

        // DS certificate only came into existence in February — it never vouched for a January signature.
        val trust = TestTrust(issuerKey.publicKey, notBefore = Instant.parse("2026-02-01T00:00:00Z"))
        assertFailsWith<MdocException> {
            MdocVerifier(trust, now = { now }).verify(IssuerSigned.decode(bytes))
        }
    }

    @Test
    fun signedAfterTheDocumentSignerCertificateRejected(): Unit = runBlocking {
        val area = SoftwareSecureArea()
        val issuerKey = area.createKey(KeySpec(secureArea = area.id, algorithm = SigningAlgorithm.ES256))
        val deviceKey = area.createKey(KeySpec(secureArea = area.id, algorithm = SigningAlgorithm.ES256)).publicKey
        val bytes = issued(area, issuerKey, deviceKey)

        val trust = TestTrust(issuerKey.publicKey, notAfter = Instant.parse("2025-12-01T00:00:00Z"))
        assertFailsWith<MdocException> {
            MdocVerifier(trust, now = { now }).verify(IssuerSigned.decode(bytes))
        }
    }

    /** Signed inside the window passes — and stays valid even once that certificate has expired. */
    @Test
    fun signedInsideTheDocumentSignerWindowAccepted() = runBlocking {
        val area = SoftwareSecureArea()
        val issuerKey = area.createKey(KeySpec(secureArea = area.id, algorithm = SigningAlgorithm.ES256))
        val deviceKey = area.createKey(KeySpec(secureArea = area.id, algorithm = SigningAlgorithm.ES256)).publicKey
        val bytes = issued(area, issuerKey, deviceKey)

        val trust = TestTrust(
            issuerKey.publicKey,
            notBefore = Instant.parse("2025-06-01T00:00:00Z"),
            notAfter = Instant.parse("2026-03-01T00:00:00Z"), // already expired at `now`, but not when signed
        )
        val verified = MdocVerifier(trust, now = { Instant.parse("2026-06-01T00:00:00Z") })
            .verify(IssuerSigned.decode(bytes))
        assertEquals(docType, verified.docType)
    }

    /** A trust implementation that cannot supply the window leaves the step-5 certificate check out. */
    @Test
    fun missingCertificateWindowSkipsTheCheck() = runBlocking {
        val area = SoftwareSecureArea()
        val issuerKey = area.createKey(KeySpec(secureArea = area.id, algorithm = SigningAlgorithm.ES256))
        val deviceKey = area.createKey(KeySpec(secureArea = area.id, algorithm = SigningAlgorithm.ES256)).publicKey
        val bytes = issued(area, issuerKey, deviceKey)

        val verified = MdocVerifier(TestTrust(issuerKey.publicKey), now = { now }).verify(IssuerSigned.decode(bytes))
        assertEquals(docType, verified.docType)
    }

    private fun ByteArray.indexOf(sub: ByteArray): Int {
        outer@ for (i in 0..this.size - sub.size) {
            for (j in sub.indices) if (this[i + j] != sub[j]) continue@outer
            return i
        }
        throw AssertionError("subsequence not found")
    }
}
