import CborCose
import XCTest
@testable import Proximity

final class MdocNfcEngagementTests: XCTestCase {
    func testNdefLongRecord() {
        let records = [
            NdefRecord(tnf: Ndef.tnfWellKnown, type: Array("Hs".utf8), payload: [0x15]),
            NdefRecord(tnf: Ndef.tnfExternal, type: Array("iso.org:18013:deviceengagement".utf8),
                       id: Array("mdoc".utf8), payload: (0..<300).map { UInt8($0 & 0xFF) }),
        ]
        let decoded = Ndef.decodeMessage(Ndef.encodeMessage(records))
        XCTAssertEqual(decoded[1].payload, records[1].payload) // 300-byte payload → long-record path
        XCTAssertEqual(decoded[1].id, Array("mdoc".utf8))
    }

    func testHandoverSelectRoundTrip() {
        let engagement: [UInt8] = [0xA2, 0x00, 0x63, 0x31, 0x2E, 0x30]
        let uuid = (1...16).map { UInt8($0) }
        let hs = MdocNfcEngagement.buildHandoverSelect(deviceEngagement: engagement, serviceUuid: uuid, peripheralServerMode: true)
        let parsed = MdocNfcEngagement.parseHandoverSelect(hs)
        XCTAssertEqual(parsed?.deviceEngagement, engagement)
        XCTAssertEqual(parsed?.serviceUuid, uuid) // little-endian OOB → back to canonical big-endian
        XCTAssertEqual(parsed?.peripheralServerMode, true)
    }

    func testHandoverRequestRoundTrip() {
        let uuid = (1...16).map { UInt8($0) }
        let cr: [UInt8] = [0x12, 0x34]
        let re = MdocNfcEngagement.readerEngagement(version: "1.0")

        let hr = MdocNfcEngagement.buildHandoverRequest(serviceUuid: uuid, collisionResolution: cr, peripheralServerMode: false, readerEngagement: re)
        let parsed = MdocNfcEngagement.parseHandoverRequest(hr)
        XCTAssertEqual(parsed?.serviceUuid, uuid)
        XCTAssertEqual(parsed?.peripheralServerMode, false) // central client mode
        XCTAssertEqual(parsed?.readerEngagement, re)

        // A static Handover Select must not parse as a Handover Request, and vice versa.
        XCTAssertNil(MdocNfcEngagement.parseHandoverRequest(MdocNfcEngagement.buildHandoverSelect(deviceEngagement: [0xA0], serviceUuid: uuid)))
        XCTAssertNil(MdocNfcEngagement.parseHandoverSelect(hr))
    }

    func testHandoverRequestWithoutReaderEngagement() {
        let uuid = (1...16).map { UInt8($0) }
        let hr = MdocNfcEngagement.buildHandoverRequest(serviceUuid: uuid, collisionResolution: [0x00, 0x01])
        let parsed = MdocNfcEngagement.parseHandoverRequest(hr)
        XCTAssertNil(parsed?.readerEngagement)
        XCTAssertEqual(parsed?.peripheralServerMode, true) // default
    }

    /// §9.1.5.1: static handover binds `[Hs, null]`; negotiated binds `[Hs, Hr]`.
    func testSessionTranscriptHandoverShapes() {
        let hs: [UInt8] = [0x01, 0x02, 0x03]
        let hr: [UInt8] = [0x0A, 0x0B]

        guard case let .array(staticItems) = ProximitySessionTranscript.nfcHandover(hs) else { return XCTFail("not an array") }
        XCTAssertEqual(staticItems[0], .bytes(hs))
        XCTAssertEqual(staticItems[1], .null)

        guard case let .array(negItems) = ProximitySessionTranscript.nfcHandover(hs, handoverRequestMessage: hr) else { return XCTFail("not an array") }
        XCTAssertEqual(negItems[0], .bytes(hs))
        XCTAssertEqual(negItems[1], .bytes(hr))
    }
}
