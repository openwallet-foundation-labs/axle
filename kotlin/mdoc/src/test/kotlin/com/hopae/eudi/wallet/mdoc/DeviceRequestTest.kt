package com.hopae.eudi.wallet.mdoc

import com.hopae.eudi.wallet.cbor.Cbor
import com.hopae.eudi.wallet.cbor.CborDecoder
import com.hopae.eudi.wallet.cbor.CborEncoder
import com.hopae.eudi.wallet.cbor.cose.CoseSign1
import com.hopae.eudi.wallet.cbor.cose.EcPublicKey
import com.hopae.eudi.wallet.spi.KeySpec
import com.hopae.eudi.wallet.spi.SecureAreaCoseSigner
import com.hopae.eudi.wallet.spi.SigningAlgorithm
import com.hopae.eudi.wallet.testkit.SoftwareSecureArea
import kotlinx.coroutines.runBlocking
import java.time.Instant
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class DeviceRequestTest {

    private val docType = "org.iso.18013.5.1.mDL"
    private val namespace = "org.iso.18013.5.1"
    private val origin = "https://verifier.example"

    private class Fixture {
        val area = SoftwareSecureArea()
        val readerKey = runBlocking { area.createKey(KeySpec(secureArea = area.id, algorithm = SigningAlgorithm.ES256)) }
        val issuerKey = runBlocking { area.createKey(KeySpec(secureArea = area.id, algorithm = SigningAlgorithm.ES256)) }
        val deviceKey = runBlocking { area.createKey(KeySpec(secureArea = area.id, algorithm = SigningAlgorithm.ES256)) }
    }

    private fun mdoc(f: Fixture): ByteArray = runBlocking {
        MdocTestIssuer.issue(
            area = f.area, issuerKey = f.issuerKey, deviceKey = f.deviceKey.publicKey, docType = docType, namespace = namespace,
            elements = listOf("family_name" to Cbor.Text("Han"), "given_name" to Cbor.Text("Jongho"), "age_over_18" to Cbor.Bool(true)),
            x5chain = listOf(byteArrayOf(0x30, 0x01)),
            signed = Instant.parse("2026-01-01T00:00:00Z"), validFrom = Instant.parse("2026-01-01T00:00:00Z"), validUntil = Instant.parse("2027-01-01T00:00:00Z"),
        )
    }

    private fun readerTrust(key: EcPublicKey) = MdocReaderTrust { key }

    /** 18013-7 C.5: a blank/whitespace origin cannot bind the response, so the transcript is not built. */
    @Test
    fun dcApiTranscriptRejectsBlankOrigin() {
        assertFailsWith<MdocException> { MdocSessionTranscript.dcApiIsoMdoc("ZW5j", "") }
        assertFailsWith<MdocException> { MdocSessionTranscript.dcApiIsoMdoc("ZW5j", "   ") }
    }

    @Test
    fun parsesDeviceRequest() = runBlocking {
        val f = Fixture()
        val st = MdocSessionTranscript.dcApiIsoMdoc("ZW5j", origin)
        val bytes = MdocTestReader.deviceRequest(f.area, f.readerKey, docType, mapOf(namespace to listOf("family_name", "given_name")), st, listOf(byteArrayOf(0x30, 0x01)))

        val request = DeviceRequest.decode(bytes)
        assertEquals("1.0", request.version)
        val docReq = request.docRequestFor(docType)!!
        assertEquals(setOf("family_name", "given_name"), docReq.requested[namespace]!!.map { it.identifier }.toSet())
        assertTrue(docReq.readerAuth != null)
    }

    @Test
    fun verifiesReaderAuth() = runBlocking {
        val f = Fixture()
        val st = MdocSessionTranscript.dcApiIsoMdoc("ZW5j", origin)
        val bytes = MdocTestReader.deviceRequest(f.area, f.readerKey, docType, mapOf(namespace to listOf("family_name")), st, listOf(byteArrayOf(0x30, 0x01)))

        val docReq = DeviceRequest.decode(bytes).docRequestFor(docType)!!
        val info = ReaderAuth.verify(docReq, st, readerTrust(f.readerKey.publicKey))
        assertTrue(info.trusted)
    }

    @Test
    fun wrongReaderKeyRejected(): Unit = runBlocking {
        val f = Fixture()
        val wrong = f.area.createKey(KeySpec(secureArea = f.area.id, algorithm = SigningAlgorithm.ES256))
        val st = MdocSessionTranscript.dcApiIsoMdoc("ZW5j", origin)
        val bytes = MdocTestReader.deviceRequest(f.area, f.readerKey, docType, mapOf(namespace to listOf("family_name")), st, listOf(byteArrayOf(0x30, 0x01)))
        val docReq = DeviceRequest.decode(bytes).docRequestFor(docType)!!
        assertFailsWith<MdocException> { ReaderAuth.verify(docReq, st, readerTrust(wrong.publicKey)) }
    }

    @Test
    fun readerAuthBoundToSessionTranscript(): Unit = runBlocking {
        // A readerAuth signed for one transcript must not verify against a different one.
        val f = Fixture()
        val st = MdocSessionTranscript.dcApiIsoMdoc("ZW5j", origin)
        val bytes = MdocTestReader.deviceRequest(f.area, f.readerKey, docType, mapOf(namespace to listOf("family_name")), st, listOf(byteArrayOf(0x30, 0x01)))
        val docReq = DeviceRequest.decode(bytes).docRequestFor(docType)!!
        val otherSt = MdocSessionTranscript.dcApiIsoMdoc("ZW5j", "https://evil.example")
        assertFailsWith<MdocException> { ReaderAuth.verify(docReq, otherSt, readerTrust(f.readerKey.publicKey)) }
    }

    @Test
    fun orgIsoMdocDcApiRoundTrip() = runBlocking {
        // ISO 18013-7 Annex C DC API: DeviceRequest -> verify reader -> disclose -> DeviceResponse over dcapi transcript.
        val f = Fixture()
        val issuerSigned = IssuerSigned.decode(mdoc(f))
        val st = MdocSessionTranscript.dcApiIsoMdoc("ZW5j", origin)
        val requestBytes = MdocTestReader.deviceRequest(f.area, f.readerKey, docType, mapOf(namespace to listOf("family_name", "given_name")), st, listOf(byteArrayOf(0x30, 0x01)))

        val docReq = DeviceRequest.decode(requestBytes).docRequestFor(docType)!!
        assertTrue(ReaderAuth.verify(docReq, st, readerTrust(f.readerKey.publicKey)).trusted)
        val disclose = docReq.disclosable(issuerSigned)
        assertEquals(setOf("family_name", "given_name"), disclose[namespace]!!.toSet())

        val deviceResponse = MdocPresenter.deviceResponse(
            issuerSigned = issuerSigned, docType = docType, disclosed = disclose,
            sessionTranscript = st, deviceSigner = SecureAreaCoseSigner(f.area, f.deviceKey.handle, SigningAlgorithm.ES256),
        )

        fun field(c: Cbor, k: String) = (c as Cbor.CborMap).entries.first { (key, _) -> (key as? Cbor.Text)?.value == k }.second
        val document = (field(CborDecoder.decode(deviceResponse), "documents") as Cbor.Array).items.single()
        val disclosed = IssuerSigned.fromCbor(field(document, "issuerSigned")).nameSpaces[namespace]!!.map { it.item.elementIdentifier }.toSet()
        assertEquals(setOf("family_name", "given_name"), disclosed)

        // deviceSignature binds the dcapi SessionTranscript
        val deviceSignature = CoseSign1.fromCbor(field(field(document, "deviceSigned"), "deviceAuth").let { field(it, "deviceSignature") })
        val deviceNsBytes = Cbor.Tagged(24u, Cbor.Bytes(CborEncoder.encode(Cbor.CborMap(emptyList()))))
        val deviceAuth = Cbor.Array(listOf(Cbor.Text("DeviceAuthentication"), st, Cbor.Text(docType), deviceNsBytes))
        val deviceAuthBytes = CborEncoder.encode(Cbor.Tagged(24u, Cbor.Bytes(CborEncoder.encode(deviceAuth))))
        assertTrue(deviceSignature.verify(f.deviceKey.publicKey, detachedPayload = deviceAuthBytes))
    }
}
