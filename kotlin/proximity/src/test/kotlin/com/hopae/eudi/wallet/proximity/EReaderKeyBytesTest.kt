package com.hopae.eudi.wallet.proximity

import com.hopae.eudi.wallet.cbor.Cbor
import com.hopae.eudi.wallet.cbor.CborDecoder
import com.hopae.eudi.wallet.cbor.CborEncoder
import com.hopae.eudi.wallet.cbor.cose.CoseKey
import com.hopae.eudi.wallet.cbor.cose.EcPublicKey
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * ISO/IEC 18013-5 §8.1: every CBOR map used in a cryptographic operation travels as a tagged bytestring and
 * "an mdoc, mdoc reader or issuing authority infrastructure shall use these bytestrings **as they were sent
 * or received, without attempting to re-create them from the underlying maps**".
 *
 * §8.1 also declines to require canonical map-key ordering, so two peers can encode the same `EReaderKey`
 * differently and both be conformant. These tests pin that a peer's exact bytes survive into the
 * SessionTranscript — the HKDF salt for the session keys and the signed payload of `DeviceAuthentication` /
 * `ReaderAuthentication`.
 */
class EReaderKeyBytesTest {

    private val eReader = EphemeralKeyPair.generate()
    private val engagement = DeviceEngagement.qr(EphemeralKeyPair.generate().publicKey)

    /** A conformant COSE_Key a *different* implementation might send: extra `kid`, and not in our order. */
    private fun peerEncodedEReaderKey(key: EcPublicKey): ByteArray {
        val ours = CoseKey.encode(key)
        fun label(l: Long): Cbor = ours.entries.first { (k, _) -> labelOf(k) == l }.second
        val reordered = Cbor.CborMap(
            listOf(
                Cbor.int(-3) to label(-3), // y
                Cbor.int(-2) to label(-2), // x
                Cbor.int(-1) to label(-1), // crv
                Cbor.int(1) to label(1),   // kty
                Cbor.int(2) to Cbor.Bytes(byteArrayOf(0x0A)), // kid — permitted, and we do not send one
            ),
        )
        return CborEncoder.encode(Cbor.Tagged(24uL, Cbor.Bytes(CborEncoder.encode(reordered))))
    }

    private fun labelOf(c: Cbor): Long? = when (c) {
        is Cbor.UInt -> c.value.toLong()
        is Cbor.NInt -> -1L - c.n.toLong()
        else -> null
    }

    /** Sanity: such a peer really does produce different bytes than our own encoder would. */
    @Test
    fun peerEncodingDiffersFromOurs() {
        val peer = peerEncodedEReaderKey(eReader.publicKey)
        val ours = SessionMessages.eReaderKeyBytes(eReader.publicKey)
        assertFalse(peer.contentEquals(ours), "test fixture must model a differently-encoded peer")
        // …yet it decodes to the same public key, so the ECDH is unaffected — only the bytes differ.
        val decoded = SessionMessages.decodeEstablishment(
            SessionMessages.encodeEstablishment(peer, byteArrayOf(1, 2, 3)),
        )
        assertContentEquals(eReader.publicKey.x, decoded.eReaderKey.x)
        assertContentEquals(eReader.publicKey.y, decoded.eReaderKey.y)
    }

    /** The received bytestring is kept verbatim, extra labels and ordering included. */
    @Test
    fun decodeKeepsTheReceivedEReaderKeyBytes() {
        val peer = peerEncodedEReaderKey(eReader.publicKey)
        val frame = SessionMessages.encodeEstablishment(peer, byteArrayOf(9))
        assertContentEquals(peer, SessionMessages.decodeEstablishment(frame).eReaderKeyBytes)
    }

    /**
     * The heart of it: the holder must derive the transcript the *reader* bound, not one of its own making.
     * Re-creating it from the parsed key yields a different SessionTranscript — which is a different HKDF
     * salt, so session-key derivation fails outright against such a peer.
     */
    @Test
    fun transcriptBindsTheReceivedBytesNotAReEncoding() {
        val peer = peerEncodedEReaderKey(eReader.publicKey)
        val established = SessionMessages.decodeEstablishment(
            SessionMessages.encodeEstablishment(peer, byteArrayOf(0)),
        )

        val fromReceivedBytes = ProximitySessionTranscript.build(engagement, established.eReaderKeyBytes)
        val reEncodedFromKey = ProximitySessionTranscript.build(engagement, established.eReaderKey)

        assertContentEquals(peer, CborEncoder.encode((fromReceivedBytes as Cbor.Array).items[1]))
        assertFalse(
            ProximitySessionTranscript.encode(fromReceivedBytes)
                .contentEquals(ProximitySessionTranscript.encode(reEncodedFromKey)),
            "re-creating EReaderKeyBytes from the parsed map must not silently produce the same transcript",
        )
    }

    /** End to end: both sides reach the same session keys even though only one of them encoded the key. */
    @Test
    fun bothSidesDeriveTheSameSessionKeys() {
        val eDevice = EphemeralKeyPair.generate()
        val de = DeviceEngagement.qr(eDevice.publicKey)
        val peer = peerEncodedEReaderKey(eReader.publicKey)

        // Reader: binds exactly what it sends.
        val readerTranscript = ProximitySessionTranscript.encode(ProximitySessionTranscript.build(de, peer))
        val readerSession = SessionEncryption.forReader(eReader, eDevice.publicKey, readerTranscript)

        // Holder: binds exactly what it received.
        val established = SessionMessages.decodeEstablishment(
            SessionMessages.encodeEstablishment(peer, readerSession.encrypt(byteArrayOf(0x42))),
        )
        val holderTranscript = ProximitySessionTranscript.encode(
            ProximitySessionTranscript.build(de, established.eReaderKeyBytes),
        )
        assertContentEquals(readerTranscript, holderTranscript)

        val holderSession = SessionEncryption.forMdoc(eDevice, established.eReaderKey, holderTranscript)
        assertContentEquals(byteArrayOf(0x42), holderSession.decrypt(established.encryptedDeviceRequest))
    }

    /** Our own two encodings of the same key stay identical — the sender path binds what it sends. */
    @Test
    fun senderPathIsSelfConsistent() {
        val bytes = SessionMessages.eReaderKeyBytes(eReader.publicKey)
        val frame = SessionMessages.decodeEstablishment(
            SessionMessages.encodeEstablishment(eReader.publicKey, byteArrayOf(7)),
        )
        assertContentEquals(bytes, frame.eReaderKeyBytes)
        assertEquals(
            ProximitySessionTranscript.encode(ProximitySessionTranscript.build(engagement, eReader.publicKey)).toList(),
            ProximitySessionTranscript.encode(ProximitySessionTranscript.build(engagement, bytes)).toList(),
        )
    }

    /** A non-#6.24 eReaderKey is rejected rather than silently bound (§9.1.1.4 CDDL). */
    @Test
    fun rejectsUntaggedEReaderKey() {
        val bad = CborEncoder.encode(
            Cbor.CborMap(
                listOf(
                    Cbor.Text("eReaderKey") to CoseKey.encode(eReader.publicKey), // bare map, not #6.24(bstr)
                    Cbor.Text("data") to Cbor.Bytes(byteArrayOf(1)),
                ),
            ),
        )
        assertTrue(runCatching { SessionMessages.decodeEstablishment(bad) }.isFailure)
        assertTrue(CborDecoder.decode(bad) is Cbor.CborMap) // the frame itself is well-formed CBOR
    }
}
