import CborCose
import Foundation
import WalletAPI
import XCTest
@testable import Proximity

/// ISO 18013-5 §9.1.1.4 / Table 20 session termination: the `status` code round-trips, a status-only
/// frame carries no `data`, and destroying the session keys blocks further use.
final class SessionTerminationTests: XCTestCase {

    func testStatusRoundTripsThroughSessionData() throws {
        let frame = try SessionMessages.decodeSessionData(
            try SessionMessages.encodeData([UInt8]("ct".utf8), status: SessionMessages.Status.sessionTermination))
        XCTAssertEqual([UInt8]("ct".utf8), frame.data)
        XCTAssertEqual(SessionMessages.Status.sessionTermination, frame.status)
    }

    func testAStatusOnlyFrameHasNoData() throws {
        let frame = try SessionMessages.decodeSessionData(try SessionMessages.encodeStatus(SessionMessages.Status.sessionTermination))
        XCTAssertNil(frame.data)
        XCTAssertEqual(20, frame.status)
        // The data-only accessor rejects it, so callers that expect a response fail loudly.
        XCTAssertThrowsError(try SessionMessages.decodeData(try SessionMessages.encodeStatus(SessionMessages.Status.sessionEncryptionError)))
    }

    func testAPlainDataFrameHasNoStatus() throws {
        let frame = try SessionMessages.decodeSessionData(try SessionMessages.encodeData([UInt8]("x".utf8)))
        XCTAssertNil(frame.status)
        XCTAssertEqual([UInt8]("x".utf8), frame.data)
    }

    func testDestroyBlocksReuse() throws {
        let eDevice = EphemeralKeyPair()
        let eReader = EphemeralKeyPair()
        let transcript = try ProximitySessionTranscript.encode(
            try ProximitySessionTranscript.build(deviceEngagement: try DeviceEngagement.qr(eDeviceKey: eDevice.publicKey),
                                                 eReaderKey: eReader.publicKey))
        let device = try SessionEncryption.forMdoc(ephemeral: eDevice, readerPublicKey: eReader.publicKey, sessionTranscriptBytes: transcript)
        let reader = try SessionEncryption.forReader(ephemeral: eReader, devicePublicKey: eDevice.publicKey, sessionTranscriptBytes: transcript)

        // A message encrypts before destruction…
        let ct = try device.encrypt([UInt8]("secret".utf8))
        XCTAssertEqual([UInt8]("secret".utf8), try reader.decrypt(ct))

        // …and after destroy() both sides refuse to touch the keys.
        device.destroy()
        reader.destroy()
        XCTAssertThrowsError(try device.encrypt([UInt8]("again".utf8)))
        XCTAssertThrowsError(try reader.decrypt(ct))

        device.destroy() // idempotent
    }
}
