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
        XCTAssertEqual(parsed?.offersMdocPeripheralServer, true) // the reader is the central ⇒ the mdoc is the peripheral
        XCTAssertEqual(parsed?.offersMdocCentralClient, false)
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
        XCTAssertEqual(parsed?.offersMdocCentralClient, true) // default: the reader is the peripheral
        XCTAssertEqual(parsed?.offersMdocPeripheralServer, false)
    }

    /// §8.3.3.1.1.2: a Select that takes the reader's carrier names no UUID — it is the one from the Request.
    func testNegotiatedSelectWithoutCarrierUsesTheRequestUuid() {
        let engagement: [UInt8] = [0xA2, 0x00, 0x63, 0x31, 0x2E, 0x30]
        let uuid = (1...16).map { UInt8($0) }
        let hs = Ndef.encodeMessage([
            NdefRecord(tnf: Ndef.tnfWellKnown, type: Array("Hs".utf8), payload: [0x15]),
            NdefRecord(tnf: Ndef.tnfExternal, type: Array("iso.org:18013:deviceengagement".utf8),
                       id: Array("mdoc".utf8), payload: engagement),
        ])
        XCTAssertNil(MdocNfcEngagement.parseHandoverSelect(hs)) // not self-contained…
        XCTAssertNil(MdocNfcEngagement.parseHandover(hs)) // …and static handover has no Request to fall back on

        let hr = MdocNfcEngagement.buildHandoverRequest(serviceUuid: uuid, collisionResolution: [0x12, 0x34], peripheralServerMode: true)
        let parsed = MdocNfcEngagement.parseHandover(hs, handoverRequest: hr)
        XCTAssertEqual(parsed?.deviceEngagement, engagement)
        XCTAssertEqual(parsed?.serviceUuid, uuid)
        XCTAssertEqual(parsed?.peripheralServerMode, false) // the reader is the peripheral ⇒ mdoc central client mode

        // A reader offering to be the central has no UUID to lend — that mode's UUID is the mdoc's to name.
        let central = MdocNfcEngagement.buildHandoverRequest(serviceUuid: uuid, collisionResolution: [0x12, 0x34], peripheralServerMode: false)
        XCTAssertNil(MdocNfcEngagement.parseHandover(hs, handoverRequest: central))
    }

    /// Offering both modes: a second, UUID-less carrier lets the mdoc answer as the peripheral if it prefers.
    func testHandoverRequestCanOfferBothModes() {
        let uuid = (1...16).map { UInt8($0) }
        let hr = MdocNfcEngagement.buildHandoverRequest(serviceUuid: uuid, collisionResolution: [0x12, 0x34],
                                                        alsoOfferMdocPeripheralServer: true)
        let records = Ndef.decodeMessage(hr)

        // The reader's own carrier is still the one either side can dial…
        let parsed = MdocNfcEngagement.parseHandoverRequest(hr)
        XCTAssertEqual(parsed?.serviceUuid, uuid)
        XCTAssertEqual(parsed?.offersMdocCentralClient, true)
        XCTAssertEqual(parsed?.offersMdocPeripheralServer, true)

        // …and the offer for the mdoc to be the peripheral rides along under its own record id, repeating the UUID:
        // that is the service the reader proposes the mdoc advertise, and carriers without one are not expected.
        let carriers = records.filter { $0.tnf == Ndef.tnfMimeMedia }
        XCTAssertEqual(carriers.count, 2)
        XCTAssertEqual(carriers.last?.id, Array("1".utf8))
        XCTAssertEqual(carriers.last?.payload, [0x02, 0x1C, 0x01, 0x11, 0x07] + uuid.reversed())

        // Each carrier needs an Alternative Carrier record pointing at it, or the mdoc cannot select it.
        let hrPayload = records.first { $0.type == Array("Hr".utf8) }?.payload ?? []
        let acs = Ndef.decodeMessage(Array(hrPayload.dropFirst())).filter { $0.type == Array("ac".utf8) }
        XCTAssertEqual(acs.map { String(decoding: $0.payload[2..<(2 + Int($0.payload[1]))], as: UTF8.self) }, ["0", "1"])
    }

    /// The mdoc's own carrier stays authoritative whenever its Select carries one.
    func testSelectCarrierOutranksTheRequestCarrier() {
        let mdocUuid = (1...16).map { UInt8($0) }
        let readerUuid = (0..<16).map { UInt8(0x80 + $0) }
        let hs = MdocNfcEngagement.buildHandoverSelect(deviceEngagement: [0xA0], serviceUuid: mdocUuid, peripheralServerMode: true)
        let hr = MdocNfcEngagement.buildHandoverRequest(serviceUuid: readerUuid, collisionResolution: [0x00, 0x01], peripheralServerMode: true)

        let parsed = MdocNfcEngagement.parseHandover(hs, handoverRequest: hr)
        XCTAssertEqual(parsed?.serviceUuid, mdocUuid)
        XCTAssertEqual(parsed?.peripheralServerMode, true)
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

    /// §8.3.3.1.1.1: a reader may say it supports "both" roles in a single carrier, via LE Role 0x02 / 0x03,
    /// instead of sending one carrier per mode. The Multipaz test app's reader encodes its offer exactly this
    /// way, so both BLE modes have to come out of one record.
    func testReaderCarrierCanOfferBothRolesInOneRecord() {
        let uuid = (1...16).map { UInt8($0) }
        for leRole in [0x02, 0x03] {
            let parsed = MdocNfcEngagement.parseHandoverRequest(handoverRequestWithLeRole(uuid, leRole))
            XCTAssertEqual(parsed?.serviceUuid, uuid)
            XCTAssertEqual(parsed?.offersMdocCentralClient, true, "LE Role \(leRole) offers the reader as peripheral")
            XCTAssertEqual(parsed?.offersMdocPeripheralServer, true, "LE Role \(leRole) offers the reader as central")
            XCTAssertEqual(parsed?.centralClientUuid, uuid)
        }
    }

    /// An unrecognised LE Role supports neither role, so the carrier is not something either side can take.
    func testUnknownLeRoleOffersNothing() {
        let uuid = (1...16).map { UInt8($0) }
        let parsed = MdocNfcEngagement.parseHandoverRequest(handoverRequestWithLeRole(uuid, 0x7F))
        XCTAssertEqual(parsed?.offersMdocCentralClient, false)
        XCTAssertEqual(parsed?.offersMdocPeripheralServer, false)
    }

    /// A Select whose LE Role says "both": §8.3.3.1.1.1 has the reader select mdoc central client mode, and that
    /// mode's UUID is the reader's own from the Request — not the one in the Select, which §8.3.3.1.1.2 reserves
    /// for mdoc peripheral server mode.
    func testSelectOfferingBothRolesTakesCentralClientOnTheReaderUuid() {
        let mdocUuid = (1...16).map { UInt8($0) }
        let readerUuid = (0..<16).map { UInt8(0x80 + $0) }
        let hs = handoverSelectWithLeRole(mdocUuid, 0x02)
        let hr = MdocNfcEngagement.buildHandoverRequest(serviceUuid: readerUuid, collisionResolution: [0x12, 0x34], peripheralServerMode: true)

        let parsed = MdocNfcEngagement.parseHandover(hs, handoverRequest: hr)
        XCTAssertEqual(parsed?.serviceUuid, readerUuid)
        XCTAssertEqual(parsed?.peripheralServerMode, false)
    }

    /// Static handover has no Request, and §8.3.3.1.1.2 lets the mdoc's single UUID serve either mode.
    func testStaticSelectOfferingBothRolesUsesItsOwnUuid() {
        let mdocUuid = (1...16).map { UInt8($0) }
        let parsed = MdocNfcEngagement.parseHandoverSelect(handoverSelectWithLeRole(mdocUuid, 0x03))
        XCTAssertEqual(parsed?.serviceUuid, mdocUuid)
        XCTAssertEqual(parsed?.peripheralServerMode, false) // both supported ⇒ the reader picks mdoc central client
    }

    /// The UUID-less-Select fallback has to work against a reader that offered both roles in one carrier too.
    func testSelectWithoutCarrierFallsBackToABothRoleRequest() {
        let engagement: [UInt8] = [0xA2, 0x00, 0x63, 0x31, 0x2E, 0x30]
        let readerUuid = (0..<16).map { UInt8(0x80 + $0) }
        let hs = Ndef.encodeMessage([
            NdefRecord(tnf: Ndef.tnfWellKnown, type: Array("Hs".utf8), payload: [0x15]),
            NdefRecord(tnf: Ndef.tnfExternal, type: Array("iso.org:18013:deviceengagement".utf8),
                       id: Array("mdoc".utf8), payload: engagement),
        ])
        let parsed = MdocNfcEngagement.parseHandover(hs, handoverRequest: handoverRequestWithLeRole(readerUuid, 0x03))
        XCTAssertEqual(parsed?.serviceUuid, readerUuid)
        XCTAssertEqual(parsed?.peripheralServerMode, false)
    }

    /// A BLE carrier-configuration record with an arbitrary raw LE Role value, which the builders cannot emit.
    private func bleOob(_ uuid: [UInt8], _ leRole: Int, id: String = "0") -> NdefRecord {
        NdefRecord(tnf: Ndef.tnfMimeMedia, type: Array("application/vnd.bluetooth.le.oob".utf8), id: Array(id.utf8),
                   payload: [0x02, 0x1C, UInt8(leRole), 0x11, 0x07] + uuid.reversed())
    }

    private func handoverRequestWithLeRole(_ uuid: [UInt8], _ leRole: Int) -> [UInt8] {
        let ac = NdefRecord(tnf: Ndef.tnfWellKnown, type: Array("ac".utf8),
                            payload: [0x01, 0x01] + Array("0".utf8) + [0x00])
        let cr = NdefRecord(tnf: Ndef.tnfWellKnown, type: Array("cr".utf8), payload: [0x12, 0x34])
        let hr = NdefRecord(tnf: Ndef.tnfWellKnown, type: Array("Hr".utf8),
                            payload: [0x15] + Ndef.encodeMessage([cr, ac]))
        return Ndef.encodeMessage([hr, bleOob(uuid, leRole)])
    }

    private func handoverSelectWithLeRole(_ uuid: [UInt8], _ leRole: Int) -> [UInt8] {
        let ac = NdefRecord(tnf: Ndef.tnfWellKnown, type: Array("ac".utf8),
                            payload: [0x01, 0x01] + Array("0".utf8) + [0x01, 0x04] + Array("mdoc".utf8))
        let hs = NdefRecord(tnf: Ndef.tnfWellKnown, type: Array("Hs".utf8), payload: [0x15] + Ndef.encodeMessage([ac]))
        let de = NdefRecord(tnf: Ndef.tnfExternal, type: Array("iso.org:18013:deviceengagement".utf8),
                            id: Array("mdoc".utf8), payload: [0xA0])
        return Ndef.encodeMessage([hs, de, bleOob(uuid, leRole)])
    }


    /// The mdoc follows the reader's stated preference — list order first, then the LE Role bit for a carrier
    /// that supports both roles.
    func testCarrierSelectionFollowsTheReadersPreference() {
        let uuid = (1...16).map { UInt8($0) }

        // Our own reader's shape: mdoc central client listed first, mdoc peripheral server second.
        let ours = MdocNfcEngagement.parseHandoverRequest(
            MdocNfcEngagement.buildHandoverRequest(serviceUuid: uuid, collisionResolution: [0x12, 0x34],
                                                   alsoOfferMdocPeripheralServer: true))?.selectCarrier()
        XCTAssertEqual(ours?.peripheralServerMode, false)
        XCTAssertEqual(ours?.serviceUuid, uuid)

        // …and reversed, the same reader would get mdoc peripheral server, where the mdoc names its own UUID.
        let reversed = MdocNfcEngagement.parseHandoverRequest(
            MdocNfcEngagement.buildHandoverRequest(serviceUuid: uuid, collisionResolution: [0x12, 0x34],
                                                   peripheralServerMode: false))?.selectCarrier()
        XCTAssertEqual(reversed?.peripheralServerMode, true)
        XCTAssertNil(reversed?.serviceUuid)

        // One carrier, both roles: 0x02 = the reader prefers Peripheral ⇒ mdoc central client…
        let peripheralPreferred = MdocNfcEngagement.parseHandoverRequest(handoverRequestWithLeRole(uuid, 0x02))?.selectCarrier()
        XCTAssertEqual(peripheralPreferred?.peripheralServerMode, false)
        XCTAssertEqual(peripheralPreferred?.serviceUuid, uuid)

        // …and 0x03 = it prefers Central ⇒ mdoc peripheral server. This is what the Multipaz reader sends.
        let centralPreferred = MdocNfcEngagement.parseHandoverRequest(handoverRequestWithLeRole(uuid, 0x03))?.selectCarrier()
        XCTAssertEqual(centralPreferred?.peripheralServerMode, true)
        XCTAssertNil(centralPreferred?.serviceUuid)

        // A Request offering no BLE role at all leaves the mdoc nothing to select.
        XCTAssertNil(MdocNfcEngagement.parseHandoverRequest(handoverRequestWithLeRole(uuid, 0x7F))?.selectCarrier())
    }
}
