package com.hopae.eudi.wallet.proximity

import com.hopae.eudi.wallet.cbor.Cbor
import com.hopae.eudi.wallet.cbor.CborDecoder
import com.hopae.eudi.wallet.cbor.CborEncoder
import com.hopae.eudi.wallet.cbor.Hkdf
import com.hopae.eudi.wallet.cbor.cose.CoseMac0
import com.hopae.eudi.wallet.cbor.cose.CoseSign1
import com.hopae.eudi.wallet.mdoc.IssuerSigned
import com.hopae.eudi.wallet.mdoc.MdocPresenter
import com.hopae.eudi.wallet.mdoc.MdocTestIssuer
import com.hopae.eudi.wallet.spi.KeySpec
import com.hopae.eudi.wallet.spi.SecureAreaCoseSigner
import com.hopae.eudi.wallet.spi.SigningAlgorithm
import com.hopae.eudi.wallet.testkit.SoftwareSecureArea
import kotlinx.coroutines.runBlocking
import java.time.Instant
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class ProximityTest {

    private fun hex(s: String) = s.chunked(2).map { it.toInt(16).toByte() }.toByteArray()

    @Test
    fun hkdfMatchesRfc5869Vector() {
        // RFC 5869 Appendix A.1
        val okm = Hkdf.deriveSha256(
            ikm = hex("0b".repeat(22)),
            salt = hex("000102030405060708090a0b0c"),
            info = hex("f0f1f2f3f4f5f6f7f8f9"),
            length = 42,
        )
        assertContentEquals(
            hex("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"),
            okm,
        )
    }

    private fun transcriptBytes(eDevice: EphemeralKeyPair, eReader: EphemeralKeyPair): ByteArray {
        val de = DeviceEngagement.qr(eDevice.publicKey)
        return ProximitySessionTranscript.encode(ProximitySessionTranscript.build(de, eReader.publicKey))
    }

    @Test
    fun sessionKeyAgreementAndRoundTrip() {
        val eDevice = EphemeralKeyPair.generate()
        val eReader = EphemeralKeyPair.generate()
        val transcript = transcriptBytes(eDevice, eReader)

        val device = SessionEncryption.forMdoc(eDevice, eReader.publicKey, transcript)
        val reader = SessionEncryption.forReader(eReader, eDevice.publicKey, transcript)

        // device -> reader, reader -> device, then a second device message (counters advance per direction)
        assertContentEquals("hello".encodeToByteArray(), reader.decrypt(device.encrypt("hello".encodeToByteArray())))
        assertContentEquals("world".encodeToByteArray(), device.decrypt(reader.encrypt("world".encodeToByteArray())))
        assertContentEquals("again".encodeToByteArray(), reader.decrypt(device.encrypt("again".encodeToByteArray())))
    }

    @Test
    fun tamperedMessageRejected() {
        val eDevice = EphemeralKeyPair.generate()
        val eReader = EphemeralKeyPair.generate()
        val transcript = transcriptBytes(eDevice, eReader)
        val device = SessionEncryption.forMdoc(eDevice, eReader.publicKey, transcript)
        val reader = SessionEncryption.forReader(eReader, eDevice.publicKey, transcript)

        val ct = device.encrypt("secret".encodeToByteArray())
        ct[ct.size - 1] = (ct[ct.size - 1] + 1).toByte() // flip the GCM tag
        assertFailsWith<ProximityException> { reader.decrypt(ct) }
    }

    @Test
    fun mismatchedTranscriptFailsToDecrypt() {
        val eDevice = EphemeralKeyPair.generate()
        val eReader = EphemeralKeyPair.generate()
        val device = SessionEncryption.forMdoc(eDevice, eReader.publicKey, transcriptBytes(eDevice, eReader))
        // reader derives keys with a different transcript -> different SK -> auth fails
        val reader = SessionEncryption.forReader(eReader, eDevice.publicKey, "other-transcript".encodeToByteArray())
        assertFailsWith<ProximityException> { reader.decrypt(device.encrypt("x".encodeToByteArray())) }
    }

    /**
     * ISO 18013-5 §9.1.3.5, the interop-critical property: the mdoc derives the `EMacKey` from
     * ECDH(DeviceKey_priv, EReaderKey_pub) inside its secure area, the reader from
     * ECDH(EReaderKey_priv, DeviceKey_pub). Different halves, identical bytes — otherwise `deviceMac`
     * never verifies against a conformant peer.
     */
    @Test
    fun holderAndReaderDeriveTheSameEMacKey() = runBlocking {
        val area = SoftwareSecureArea()
        val deviceKey = area.createKey(KeySpec(secureArea = area.id, algorithm = SigningAlgorithm.ES256))
        val eDevice = EphemeralKeyPair.generate()
        val eReader = EphemeralKeyPair.generate()
        val transcript = ProximitySessionTranscript.build(DeviceEngagement.qr(eDevice.publicKey), eReader.publicKey)
        val transcriptBytes = ProximitySessionTranscript.encode(transcript)

        val holder = SessionEncryption.emacKey(area.keyAgreement(deviceKey.handle, eReader.publicKey), transcriptBytes)
        val reader = SessionEncryption.deriveEMacKey(eReader, deviceKey.publicKey, transcriptBytes)

        assertContentEquals(reader, holder)
        assertEquals(32, holder.size)
    }

    /** A deviceMac built by the holder verifies against the EMacKey the reader independently derives. */
    @Test
    fun deviceMacOverProximityTranscriptVerifies() = runBlocking {
        val docType = "org.iso.18013.5.1.mDL"
        val namespace = "org.iso.18013.5.1"
        val area = SoftwareSecureArea()
        val issuerKey = area.createKey(KeySpec(secureArea = area.id, algorithm = SigningAlgorithm.ES256))
        val deviceKey = area.createKey(KeySpec(secureArea = area.id, algorithm = SigningAlgorithm.ES256))
        val mdocBytes = MdocTestIssuer.issue(
            area = area, issuerKey = issuerKey, deviceKey = deviceKey.publicKey, docType = docType, namespace = namespace,
            elements = listOf("family_name" to Cbor.Text("Han")),
            x5chain = listOf(byteArrayOf(0x30, 0x01)),
            signed = Instant.parse("2026-01-01T00:00:00Z"), validFrom = Instant.parse("2026-01-01T00:00:00Z"),
            validUntil = Instant.parse("2027-01-01T00:00:00Z"),
        )

        val eDevice = EphemeralKeyPair.generate()
        val eReader = EphemeralKeyPair.generate()
        val sessionTranscript = ProximitySessionTranscript.build(DeviceEngagement.qr(eDevice.publicKey), eReader.publicKey)
        val transcriptBytes = ProximitySessionTranscript.encode(sessionTranscript)

        // holder side: Zab from the secure area, never exposing DeviceKey's private half
        val emacKey = SessionEncryption.emacKey(area.keyAgreement(deviceKey.handle, eReader.publicKey), transcriptBytes)
        val deviceResponse = MdocPresenter.deviceResponse(
            issuerSigned = IssuerSigned.decode(mdocBytes), docType = docType,
            disclosed = mapOf(namespace to listOf("family_name")),
            sessionTranscript = sessionTranscript,
            deviceAuth = com.hopae.eudi.wallet.mdoc.DeviceAuth.Mac(emacKey),
        )

        // reader side: derive the EMacKey from its own ephemeral half and verify the MAC
        fun map(c: Cbor, k: String) = (c as Cbor.CborMap).entries.first { (key, _) -> (key as? Cbor.Text)?.value == k }.second
        val document = (map(CborDecoder.decode(deviceResponse), "documents") as Cbor.Array).items.single()
        val deviceMac = CoseMac0.fromCbor(map(map(document, "deviceSigned"), "deviceAuth").let { map(it, "deviceMac") })
        val deviceNsBytes = Cbor.Tagged(24u, Cbor.Bytes(CborEncoder.encode(Cbor.CborMap(emptyList()))))
        val deviceAuth = Cbor.Array(listOf(Cbor.Text("DeviceAuthentication"), sessionTranscript, Cbor.Text(docType), deviceNsBytes))
        val deviceAuthBytes = CborEncoder.encode(Cbor.Tagged(24u, Cbor.Bytes(CborEncoder.encode(deviceAuth))))

        val readerKey = SessionEncryption.deriveEMacKey(eReader, deviceKey.publicKey, transcriptBytes)
        assert(deviceMac.verify(readerKey, detachedPayload = deviceAuthBytes)) { "deviceMac must bind the proximity SessionTranscript" }
    }

    @Test
    fun deviceResponseSignedOverProximityTranscript() = runBlocking {
        val docType = "org.iso.18013.5.1.mDL"
        val namespace = "org.iso.18013.5.1"
        val area = SoftwareSecureArea()
        val issuerKey = area.createKey(KeySpec(secureArea = area.id, algorithm = SigningAlgorithm.ES256))
        val deviceKey = area.createKey(KeySpec(secureArea = area.id, algorithm = SigningAlgorithm.ES256))
        val mdocBytes = MdocTestIssuer.issue(
            area = area, issuerKey = issuerKey, deviceKey = deviceKey.publicKey, docType = docType, namespace = namespace,
            elements = listOf("family_name" to Cbor.Text("Han"), "given_name" to Cbor.Text("Jongho")),
            x5chain = listOf(byteArrayOf(0x30, 0x01)),
            signed = Instant.parse("2026-01-01T00:00:00Z"), validFrom = Instant.parse("2026-01-01T00:00:00Z"), validUntil = Instant.parse("2027-01-01T00:00:00Z"),
        )

        val eDevice = EphemeralKeyPair.generate()
        val eReader = EphemeralKeyPair.generate()
        val sessionTranscript = ProximitySessionTranscript.build(DeviceEngagement.qr(eDevice.publicKey), eReader.publicKey)

        val deviceResponse = MdocPresenter.deviceResponse(
            issuerSigned = IssuerSigned.decode(mdocBytes), docType = docType,
            disclosed = mapOf(namespace to listOf("family_name")),
            sessionTranscript = sessionTranscript,
            deviceSigner = SecureAreaCoseSigner(area, deviceKey.handle, SigningAlgorithm.ES256),
        )

        // verify deviceSignature over the reconstructed proximity DeviceAuthenticationBytes
        fun map(c: Cbor, k: String) = (c as Cbor.CborMap).entries.first { (key, _) -> (key as? Cbor.Text)?.value == k }.second
        val document = (map(CborDecoder.decode(deviceResponse), "documents") as Cbor.Array).items.single()
        val deviceSignature = CoseSign1.fromCbor(map(map(document, "deviceSigned"), "deviceAuth").let { map(it, "deviceSignature") })
        val deviceNsBytes = Cbor.Tagged(24u, Cbor.Bytes(CborEncoder.encode(Cbor.CborMap(emptyList()))))
        val deviceAuth = Cbor.Array(listOf(Cbor.Text("DeviceAuthentication"), sessionTranscript, Cbor.Text(docType), deviceNsBytes))
        val deviceAuthBytes = CborEncoder.encode(Cbor.Tagged(24u, Cbor.Bytes(CborEncoder.encode(deviceAuth))))
        assert(deviceSignature.verify(deviceKey.publicKey, detachedPayload = deviceAuthBytes)) { "deviceSignature must bind the proximity SessionTranscript" }

        // and only the disclosed element is present
        val disclosed = IssuerSigned.fromCbor(map(document, "issuerSigned")).nameSpaces[namespace]!!.map { it.item.elementIdentifier }
        assertEquals(listOf("family_name"), disclosed)
    }
}
