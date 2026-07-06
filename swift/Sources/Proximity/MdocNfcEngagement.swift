/// A parsed ISO 18013-5 NFC static handover: the DeviceEngagement + the BLE carrier (service UUID, mode).
public struct NfcEngagement {
    public let deviceEngagement: [UInt8]
    public let serviceUuid: [UInt8]
    public let peripheralServerMode: Bool
}

/// ISO/IEC 18013-5 §8.3.3.1.2 NFC **static handover** — the mdoc serves a Handover Select NDEF message
/// (`Hs` record + a `DeviceEngagement` record + a BLE carrier-configuration record). The reader reads it,
/// extracts the engagement + BLE service UUID, and the connection continues over BLE. The full Handover
/// Select message is bound into the SessionTranscript via `ProximitySessionTranscript.nfcHandover`.
public enum MdocNfcEngagement {
    private static let handoverVersion: UInt8 = 0x15 // Connection Handover 1.5
    private static let oobMime = Array("application/vnd.bluetooth.le.oob".utf8)
    private static let deType = Array("iso.org:18013:deviceengagement".utf8)
    private static let adLeRole = 0x1C
    private static let adUuid128 = 0x07

    /// Builds the static Handover Select NDEF message. `serviceUuid` is the 16-byte big-endian BLE service UUID.
    public static func buildHandoverSelect(deviceEngagement: [UInt8], serviceUuid: [UInt8], peripheralServerMode: Bool = true) -> [UInt8] {
        // Alternative Carrier record (embedded in the Hs record): CPS active, carrier "0", aux "mdoc".
        let mdoc = Array("mdoc".utf8)
        let ac = NdefRecord(tnf: Ndef.tnfWellKnown, type: Array("ac".utf8),
                            payload: [0x01, 0x01, UInt8(ascii: "0"), 0x01, 0x04] + mdoc)
        let hs = NdefRecord(tnf: Ndef.tnfWellKnown, type: Array("Hs".utf8),
                            payload: [handoverVersion] + Ndef.encodeMessage([ac]))
        let de = NdefRecord(tnf: Ndef.tnfExternal, type: deType, id: mdoc, payload: deviceEngagement)

        // BLE carrier config: LE Role (reader's role) + the 128-bit UUID, little-endian (reversed canonical).
        let leRole: UInt8 = peripheralServerMode ? 0x00 : 0x01
        let oobPayload: [UInt8] = [0x02, UInt8(adLeRole), leRole, 0x11, UInt8(adUuid128)] + serviceUuid.reversed()
        let oob = NdefRecord(tnf: Ndef.tnfMimeMedia, type: oobMime, id: [UInt8(ascii: "0")], payload: oobPayload)

        return Ndef.encodeMessage([hs, de, oob])
    }

    /// Parses a static Handover Select NDEF message → the DeviceEngagement, BLE service UUID (big-endian), and mode.
    public static func parseHandoverSelect(_ ndef: [UInt8]) -> NfcEngagement? {
        let records = Ndef.decodeMessage(ndef)
        guard let hs = records.first(where: { $0.tnf == Ndef.tnfWellKnown && $0.type == Array("Hs".utf8) }),
              hs.payload.first == handoverVersion,
              let de = records.first(where: { $0.tnf == Ndef.tnfExternal && $0.type == deType })?.payload,
              let oob = records.first(where: { $0.tnf == Ndef.tnfMimeMedia && $0.type == oobMime })
        else { return nil }

        var i = 0
        var leRole = 0
        var uuid: [UInt8]?
        let p = oob.payload
        while i < p.count {
            let len = Int(p[i])
            if len == 0 || i + 1 + len > p.count { break }
            let data = Array(p[(i + 2)..<(i + 1 + len)])
            switch Int(p[i + 1]) {
            case adLeRole: if let first = data.first { leRole = Int(first) }
            case adUuid128: if data.count == 16 { uuid = data.reversed() } // little-endian → canonical big-endian
            default: break
            }
            i += 1 + len
        }
        guard let serviceUuid = uuid else { return nil }
        return NfcEngagement(deviceEngagement: de, serviceUuid: serviceUuid, peripheralServerMode: leRole == 0x00)
    }
}
