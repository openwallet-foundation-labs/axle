import CborCose

/// A parsed ISO 18013-5 NFC static handover: the DeviceEngagement + the BLE carrier (service UUID, mode).
public struct NfcEngagement {
    public let deviceEngagement: [UInt8]
    public let serviceUuid: [UInt8]
    public let peripheralServerMode: Bool
}

/// A parsed ISO 18013-5 NFC negotiated Handover Request: the reader's BLE carrier + optional ReaderEngagement.
public struct NfcHandoverRequest {
    public let serviceUuid: [UInt8]
    public let peripheralServerMode: Bool
    public let readerEngagement: [UInt8]?
}

/// ISO/IEC 18013-5 §8.2.2.1 / §8.3.3.1.2 NFC handover.
///
/// **Static handover** — the mdoc serves a Handover Select NDEF message (`Hs` record + a `DeviceEngagement`
/// record + a BLE carrier-configuration record). The reader reads it, extracts the engagement + BLE service
/// UUID, and the connection continues over BLE.
///
/// **Negotiated handover** — the mdoc reader (Handover Requester) sends a Handover Request NDEF message
/// (`Hr` record + a collision-resolution record + the reader's carrier(s), optionally a `ReaderEngagement`
/// aux record); the mdoc confirms with a Handover Select carrying exactly one selected carrier. Both the
/// Handover Select **and** the Handover Request are bound into the SessionTranscript via
/// `ProximitySessionTranscript.nfcHandover`; static handover binds only the Select (request = null).
public enum MdocNfcEngagement {
    private static let handoverVersion: UInt8 = 0x15 // Connection Handover 1.5
    private static let oobMime = Array("application/vnd.bluetooth.le.oob".utf8)
    private static let deType = Array("iso.org:18013:deviceengagement".utf8)
    private static let reType = Array("iso.org:18013:readerengagement".utf8)
    private static let adLeRole = 0x1C
    private static let adUuid128 = 0x07

    /// Builds the static Handover Select NDEF message. `serviceUuid` is the 16-byte big-endian BLE service UUID.
    public static func buildHandoverSelect(deviceEngagement: [UInt8], serviceUuid: [UInt8], peripheralServerMode: Bool = true) -> [UInt8] {
        let hs = NdefRecord(tnf: Ndef.tnfWellKnown, type: Array("Hs".utf8),
                            payload: [handoverVersion] + Ndef.encodeMessage([acRecord("mdoc")]))
        let de = NdefRecord(tnf: Ndef.tnfExternal, type: deType, id: Array("mdoc".utf8), payload: deviceEngagement)
        return Ndef.encodeMessage([hs, de, bleOobRecord(serviceUuid, peripheralServerMode)])
    }

    /// Parses a static Handover Select NDEF message → the DeviceEngagement, BLE service UUID (big-endian), and mode.
    public static func parseHandoverSelect(_ ndef: [UInt8]) -> NfcEngagement? {
        let records = Ndef.decodeMessage(ndef)
        guard hasHandover(records, "Hs"),
              let de = records.first(where: { $0.tnf == Ndef.tnfExternal && $0.type == deType })?.payload,
              let (uuid, peripheralServerMode) = parseOob(records)
        else { return nil }
        return NfcEngagement(deviceEngagement: de, serviceUuid: uuid, peripheralServerMode: peripheralServerMode)
    }

    /// Builds the negotiated-handover Handover Request NDEF message the mdoc **reader** sends to the mdoc
    /// (§8.2.2.1): an `Hr` record (version + collision-resolution record + one Alternative Carrier) plus the
    /// BLE carrier-configuration record, and optionally a `ReaderEngagement` auxiliary record.
    /// `collisionResolution` is the 2-byte random the reader picks (NFC Forum CH); `serviceUuid` is the
    /// 16-byte big-endian BLE service UUID.
    public static func buildHandoverRequest(
        serviceUuid: [UInt8],
        collisionResolution: [UInt8],
        peripheralServerMode: Bool = true,
        readerEngagement: [UInt8]? = nil
    ) -> [UInt8] {
        let cr = NdefRecord(tnf: Ndef.tnfWellKnown, type: Array("cr".utf8), payload: collisionResolution)
        let hr = NdefRecord(tnf: Ndef.tnfWellKnown, type: Array("Hr".utf8),
                            payload: [handoverVersion] + Ndef.encodeMessage([cr, acRecord(readerEngagement != nil ? "mdocreader" : nil)]))
        var records = [hr]
        if let re = readerEngagement {
            records.append(NdefRecord(tnf: Ndef.tnfExternal, type: reType, id: Array("mdocreader".utf8), payload: re))
        }
        records.append(bleOobRecord(serviceUuid, peripheralServerMode))
        return Ndef.encodeMessage(records)
    }

    /// Parses a negotiated Handover Request NDEF message → the reader's BLE carrier and optional ReaderEngagement.
    public static func parseHandoverRequest(_ ndef: [UInt8]) -> NfcHandoverRequest? {
        let records = Ndef.decodeMessage(ndef)
        guard hasHandover(records, "Hr"), let (uuid, peripheralServerMode) = parseOob(records) else { return nil }
        let re = records.first(where: { $0.tnf == Ndef.tnfExternal && $0.type == reType })?.payload
        return NfcHandoverRequest(serviceUuid: uuid, peripheralServerMode: peripheralServerMode, readerEngagement: re)
    }

    /// Minimal ReaderEngagement (§8.2.2.1): `{0: version}` — a reader-supplied structure carried as Hr aux data.
    public static func readerEngagement(version: String = "1.0") -> [UInt8] {
        (try? CborEncoder.encode(.map([(.uint(0), .text(version))]))) ?? []
    }

    /// True when the message opens with a Handover record (`kind` = "Hs" or "Hr") of the supported CH version.
    private static func hasHandover(_ records: [NdefRecord], _ kind: String) -> Bool {
        guard let h = records.first(where: { $0.tnf == Ndef.tnfWellKnown && $0.type == Array(kind.utf8) }) else { return false }
        return h.payload.first == handoverVersion
    }

    /// An Alternative Carrier record: active carrier, data reference "0", optional single aux-data reference.
    private static func acRecord(_ auxRef: String?) -> NdefRecord {
        let head: [UInt8] = [0x01, 0x01, UInt8(ascii: "0")] // CPS=active, carrier-data-ref "0"
        let aux: [UInt8] = auxRef.map { [0x01, UInt8($0.utf8.count)] + Array($0.utf8) } ?? [0x00]
        return NdefRecord(tnf: Ndef.tnfWellKnown, type: Array("ac".utf8), payload: head + aux)
    }

    /// BLE carrier-config record (id "0"): LE Role + the 128-bit service UUID written little-endian.
    private static func bleOobRecord(_ serviceUuid: [UInt8], _ peripheralServerMode: Bool) -> NdefRecord {
        let leRole: UInt8 = peripheralServerMode ? 0x00 : 0x01
        let oobPayload: [UInt8] = [0x02, UInt8(adLeRole), leRole, 0x11, UInt8(adUuid128)] + serviceUuid.reversed()
        return NdefRecord(tnf: Ndef.tnfMimeMedia, type: oobMime, id: [UInt8(ascii: "0")], payload: oobPayload)
    }

    /// Reads the BLE service UUID (returned big-endian) and mode from the OOB carrier-config record.
    private static func parseOob(_ records: [NdefRecord]) -> ([UInt8], Bool)? {
        guard let oob = records.first(where: { $0.tnf == Ndef.tnfMimeMedia && $0.type == oobMime }) else { return nil }
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
        return (serviceUuid, leRole == 0x00)
    }
}
