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
}
