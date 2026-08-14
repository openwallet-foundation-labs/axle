import CborCose
import Foundation
import XCTest
@testable import Proximity

/// ISO/IEC 18013-5 §8.1: every CBOR map used in a cryptographic operation travels as a tagged bytestring and
/// "an mdoc, mdoc reader or issuing authority infrastructure shall use these bytestrings **as they were sent
/// or received, without attempting to re-create them from the underlying maps**".
///
/// §8.1 also declines to require canonical map-key ordering, so two peers can encode the same `EReaderKey`
/// differently and both be conformant. These tests pin that a peer's exact bytes survive into the
/// SessionTranscript — the HKDF salt for the session keys and the signed payload of `DeviceAuthentication` /
/// `ReaderAuthentication`.
final class EReaderKeyBytesTests: XCTestCase {

    private let eReader = EphemeralKeyPair()

    private func engagement() throws -> [UInt8] {
        try DeviceEngagement.qr(eDeviceKey: EphemeralKeyPair().publicKey)
    }

    /// A conformant COSE_Key a *different* implementation might send: extra `kid`, and not in our order.
    private func peerEncodedEReaderKey(_ key: EcPublicKey) throws -> [UInt8] {
        guard case let .map(ours) = CoseKey.encode(key) else { XCTFail("COSE_Key must be a map"); return [] }
        func label(_ l: Int64) -> Cbor { ours.first { labelOf($0.0) == l }!.1 }
        let reordered = Cbor.map([
            (.int(-3), label(-3)), // y
            (.int(-2), label(-2)), // x
            (.int(-1), label(-1)), // crv
            (.int(1), label(1)),   // kty
            (.int(2), .bytes([0x0A])), // kid — permitted, and we do not send one
        ])
        return try CborEncoder.encode(.tagged(24, .bytes(try CborEncoder.encode(reordered))))
    }

    private func labelOf(_ c: Cbor) -> Int64? {
        switch c {
        case let .uint(v): return Int64(v)
        case let .nint(n): return -1 - Int64(n)
        default: return nil
        }
    }

    /// Sanity: such a peer really does produce different bytes than our own encoder would.
    func testPeerEncodingDiffersFromOurs() throws {
        let peer = try peerEncodedEReaderKey(eReader.publicKey)
        let ours = try SessionMessages.eReaderKeyBytes(eReader.publicKey)
        XCTAssertNotEqual(peer, ours, "test fixture must model a differently-encoded peer")
        // …yet it decodes to the same public key, so the ECDH is unaffected — only the bytes differ.
        let decoded = try SessionMessages.decodeEstablishment(
            try SessionMessages.encodeEstablishment(eReaderKeyBytes: peer, encryptedDeviceRequest: [1, 2, 3]))
        XCTAssertEqual(eReader.publicKey.x, decoded.eReaderKey.x)
        XCTAssertEqual(eReader.publicKey.y, decoded.eReaderKey.y)
    }

    /// The received bytestring is kept verbatim, extra labels and ordering included.
    func testDecodeKeepsTheReceivedEReaderKeyBytes() throws {
        let peer = try peerEncodedEReaderKey(eReader.publicKey)
        let frame = try SessionMessages.encodeEstablishment(eReaderKeyBytes: peer, encryptedDeviceRequest: [9])
        XCTAssertEqual(peer, try SessionMessages.decodeEstablishment(frame).eReaderKeyBytes)
    }

    /// The heart of it: the holder must derive the transcript the *reader* bound, not one of its own making.
    /// Re-creating it from the parsed key yields a different SessionTranscript — a different HKDF salt, so
    /// session-key derivation fails outright against such a peer.
    func testTranscriptBindsTheReceivedBytesNotAReEncoding() throws {
        let de = try engagement()
        let peer = try peerEncodedEReaderKey(eReader.publicKey)
        let established = try SessionMessages.decodeEstablishment(
            try SessionMessages.encodeEstablishment(eReaderKeyBytes: peer, encryptedDeviceRequest: [0]))

        let fromReceivedBytes = try ProximitySessionTranscript.build(
            deviceEngagement: de, eReaderKeyBytes: established.eReaderKeyBytes)
        let reEncodedFromKey = try ProximitySessionTranscript.build(
            deviceEngagement: de, eReaderKey: established.eReaderKey)

        guard case let .array(items) = fromReceivedBytes else { return XCTFail("transcript must be an array") }
        XCTAssertEqual(peer, try CborEncoder.encode(items[1]))
        XCTAssertNotEqual(
            try ProximitySessionTranscript.encode(fromReceivedBytes),
            try ProximitySessionTranscript.encode(reEncodedFromKey),
            "re-creating EReaderKeyBytes from the parsed map must not silently produce the same transcript")
    }

    /// End to end: both sides reach the same session keys even though only one of them encoded the key.
    func testBothSidesDeriveTheSameSessionKeys() throws {
        let eDevice = EphemeralKeyPair()
        let de = try DeviceEngagement.qr(eDeviceKey: eDevice.publicKey)
        let peer = try peerEncodedEReaderKey(eReader.publicKey)

        // Reader: binds exactly what it sends.
        let readerTranscript = try ProximitySessionTranscript.encode(
            try ProximitySessionTranscript.build(deviceEngagement: de, eReaderKeyBytes: peer))
        let readerSession = try SessionEncryption.forReader(
            ephemeral: eReader, devicePublicKey: eDevice.publicKey, sessionTranscriptBytes: readerTranscript)

        // Holder: binds exactly what it received.
        let established = try SessionMessages.decodeEstablishment(
            try SessionMessages.encodeEstablishment(
                eReaderKeyBytes: peer, encryptedDeviceRequest: try readerSession.encrypt([0x42])))
        let holderTranscript = try ProximitySessionTranscript.encode(
            try ProximitySessionTranscript.build(deviceEngagement: de, eReaderKeyBytes: established.eReaderKeyBytes))
        XCTAssertEqual(readerTranscript, holderTranscript)

        let holderSession = try SessionEncryption.forMdoc(
            ephemeral: eDevice, readerPublicKey: established.eReaderKey, sessionTranscriptBytes: holderTranscript)
        XCTAssertEqual([0x42], try holderSession.decrypt(established.encryptedDeviceRequest))
    }

    /// Our own two encodings of the same key stay identical — the sender path binds what it sends.
    func testSenderPathIsSelfConsistent() throws {
        let de = try engagement()
        let bytes = try SessionMessages.eReaderKeyBytes(eReader.publicKey)
        let frame = try SessionMessages.decodeEstablishment(
            try SessionMessages.encodeEstablishment(eReaderKey: eReader.publicKey, encryptedDeviceRequest: [7]))
        XCTAssertEqual(bytes, frame.eReaderKeyBytes)
        XCTAssertEqual(
            try ProximitySessionTranscript.encode(
                try ProximitySessionTranscript.build(deviceEngagement: de, eReaderKey: eReader.publicKey)),
            try ProximitySessionTranscript.encode(
                try ProximitySessionTranscript.build(deviceEngagement: de, eReaderKeyBytes: bytes)))
    }

    /// A non-#6.24 eReaderKey is rejected rather than silently bound (§9.1.1.4 CDDL).
    func testRejectsUntaggedEReaderKey() throws {
        let bad = try CborEncoder.encode(.map([
            (.text("eReaderKey"), CoseKey.encode(eReader.publicKey)), // bare map, not #6.24(bstr)
            (.text("data"), .bytes([1])),
        ]))
        XCTAssertThrowsError(try SessionMessages.decodeEstablishment(bad))
    }
}
