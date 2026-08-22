import CborCose

/// A parsed ISO 18013-5 NFC static handover: the DeviceEngagement + the BLE carrier (service UUID, mode).
public struct NfcEngagement {
    public let deviceEngagement: [UInt8]
    public let serviceUuid: [UInt8]
    public let peripheralServerMode: Bool
}

/// One BLE carrier-configuration record of an NFC handover message: the service UUID it names (big-endian, nil
/// when the record carries none) and the raw Bluetooth CSS **LE Role** (0x1C) value.
///
/// LE Role always describes the record's **sender**, and it has four defined values — the two "supports both"
/// ones matter in practice: ISO 18013-5 §8.3.3.1.1.1 says an mdoc or mdoc reader "indicates whether it supports
/// the Central role, the Peripheral role **or both**", and readers in the field (the Multipaz test app) offer
/// both BLE modes in a single carrier record that way rather than by sending two records.
///
/// | value | meaning                              |
/// |-------|--------------------------------------|
/// | 0x00  | only Peripheral supported            |
/// | 0x01  | only Central supported               |
/// | 0x02  | both supported, Peripheral preferred |
/// | 0x03  | both supported, Central preferred    |
///
/// An unrecognised value supports neither role, which drops the carrier from consideration.
public struct NfcBleCarrier {
    public let serviceUuid: [UInt8]?
    public let leRole: Int

    /// True when the sender can take the BLE Peripheral role (GATT server).
    public var supportsPeripheral: Bool { leRole == 0x00 || leRole == 0x02 || leRole == 0x03 }

    /// True when the sender can take the BLE Central role (GATT client).
    public var supportsCentral: Bool { leRole == 0x01 || leRole == 0x02 || leRole == 0x03 }
}

/// A parsed ISO 18013-5 NFC negotiated Handover Request: every BLE carrier the reader offered + optional
/// ReaderEngagement. The mdoc must answer with a Select naming **one of these** (§8.2.2.1), so the mode helpers
/// below are what an mdoc consults before deciding which role to take.
///
/// The LE Role in these records is the **reader's** own, so the two are inverted relative to the mdoc's mode:
/// a reader offering to be the Peripheral is offering *mdoc central client mode*, and one offering to be the
/// Central is offering *mdoc peripheral server mode*.
public struct NfcHandoverRequest {
    public let carriers: [NfcBleCarrier]
    public let readerEngagement: [UInt8]?

    /// The first carrier that names a UUID — the only address either side can dial.
    public var serviceUuid: [UInt8]? { carriers.compactMap(\.serviceUuid).first }

    /// The UUID to dial in **mdoc central client mode**: §8.3.3.1.1.2 defines the UUID in a Handover Request as
    /// exactly that ("if the mdoc reader supports mdoc central client mode, it shall include a UUID in the
    /// Handover Request message"), so it is taken from a carrier whose LE Role puts the reader in the Peripheral
    /// role. Nil when the reader never offered that mode, or offered it without an address.
    public var centralClientUuid: [UInt8]? {
        carriers.first(where: { $0.supportsPeripheral && $0.serviceUuid != nil })?.serviceUuid
    }

    /// True when the reader offered to be the BLE Peripheral, i.e. **mdoc central client mode** is on the table.
    public var offersMdocCentralClient: Bool { centralClientUuid != nil }

    /// True when the reader offered to be the BLE Central, i.e. **mdoc peripheral server mode** is on the table.
    /// That carrier needs no UUID of the reader's — the mdoc names its own in the Handover Select.
    public var offersMdocPeripheralServer: Bool { carriers.contains { $0.supportsCentral } }

    /// The carrier an mdoc should take, or nil when the Request offers no BLE mode at all.
    ///
    /// §8.2.2.1 lets the mdoc select **one** of the carriers the reader offered, and the reader states which it
    /// would rather have twice over: by the order it lists them in (Connection Handover lists alternative
    /// carriers most-preferred first) and, for a carrier that supports both roles, by the LE Role preference bit
    /// (0x02 = the reader would rather be the Peripheral ⇒ *mdoc central client mode*; 0x03 = it would rather be
    /// the Central ⇒ *mdoc peripheral server mode*). This walks the list in order and honours that — which is
    /// also what the mdocs seen in the field do, and it is how a reader gets to steer the exchange at all.
    ///
    /// Where the reader expresses no preference, mdoc central client mode wins: §8.3.3.1.1.1 says a reader
    /// *should* select it when the mdoc supports both, Google Wallet always picks it, and it keeps the mdoc off
    /// the air — the reader advertises, the mdoc only scans.
    public func selectCarrier() -> NfcCarrierChoice? {
        for carrier in carriers {
            // The reader taking one role is the mdoc taking the other. Central client also needs an address:
            // §8.3.3.1.1.2 puts that UUID in the Request, and without it there is nothing for the mdoc to dial.
            let mdocCentralClient = carrier.supportsPeripheral && carrier.serviceUuid != nil
            let mdocPeripheralServer = carrier.supportsCentral
            if mdocCentralClient, mdocPeripheralServer {
                return carrier.leRole == 0x02
                    ? NfcCarrierChoice(peripheralServerMode: false, serviceUuid: carrier.serviceUuid)
                    : NfcCarrierChoice(peripheralServerMode: true, serviceUuid: nil)
            }
            if mdocCentralClient { return NfcCarrierChoice(peripheralServerMode: false, serviceUuid: carrier.serviceUuid) }
            if mdocPeripheralServer { return NfcCarrierChoice(peripheralServerMode: true, serviceUuid: nil) }
            // nothing dialable in this record — try the next carrier
        }
        return nil
    }
}

/// The BLE mode an mdoc takes out of a negotiated Handover Request, from `NfcHandoverRequest.selectCarrier()`.
/// `serviceUuid` is set only for **mdoc central client mode**, where the address is the reader's; in mdoc
/// peripheral server mode the mdoc names its own UUID in the Handover Select and this is nil.
public struct NfcCarrierChoice {
    public let peripheralServerMode: Bool
    public let serviceUuid: [UInt8]?
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

    /// Bluetooth CSS LE Role values, as modelled by `NfcBleCarrier`. Always the **sender's own** role, which on
    /// a Handover Request inverts against the ISO mode names: mdoc central client mode has the *reader* as the
    /// peripheral, so a reader asking for it sends `leBothPeripheralPreferred`, not the central-preferred one.
    private static let lePeripheralOnly = 0x00
    private static let leCentralOnly = 0x01
    private static let leBothPeripheralPreferred = 0x02

    /// Builds the static Handover Select NDEF message. `serviceUuid` is the 16-byte big-endian BLE service UUID.
    public static func buildHandoverSelect(deviceEngagement: [UInt8], serviceUuid: [UInt8], peripheralServerMode: Bool = true) -> [UInt8] {
        let hs = NdefRecord(tnf: Ndef.tnfWellKnown, type: Array("Hs".utf8),
                            payload: [handoverVersion] + Ndef.encodeMessage([acRecord("mdoc")]))
        let de = NdefRecord(tnf: Ndef.tnfExternal, type: deType, id: Array("mdoc".utf8), payload: deviceEngagement)
        return Ndef.encodeMessage([hs, de, bleOobRecord(serviceUuid, peripheralServerMode ? lePeripheralOnly : leCentralOnly)])
    }

    /// Parses a Handover Select NDEF message on its own → the DeviceEngagement, BLE service UUID (big-endian),
    /// and the mdoc's mode. Self-contained by construction, so this is the **static handover** entry point;
    /// negotiated handover needs the Request too and goes through `parseHandover`.
    public static func parseHandoverSelect(_ ndef: [UInt8]) -> NfcEngagement? {
        parseHandover(ndef, handoverRequest: nil)
    }

    /// Resolves the carrier of a finished handover: the DeviceEngagement, the UUID to dial, and which BLE mode
    /// the mdoc took. The Handover Select alone does not always determine that, so pass the Handover Request
    /// whenever there was one (negotiated handover); `handoverRequest` = nil is static handover, where the
    /// Select must be self-contained.
    ///
    /// Three §8.3.3.1.1 rules meet here:
    /// - The UUID's meaning depends on the message it travels in. In the **Select** it is the mdoc's own, "to be
    ///   used for mdoc peripheral server mode"; in the **Request** it is the reader's, "to be used for mdoc
    ///   central client mode". A Select that takes the reader's carrier therefore names no UUID at all and only
    ///   the pair identifies the connection.
    /// - LE Role says which roles the **mdoc** supports, and "both" is a first-class answer (0x02 / 0x03).
    /// - When the mdoc supports both, "the mdoc reader should select the mdoc central client mode" — which also
    ///   settles the UUID: mdoc central client mode dials the *reader's*, not the one in the Select. Static
    ///   handover is the exception the spec calls out, where the mdoc's single UUID serves either mode.
    public static func parseHandover(_ handoverSelect: [UInt8], handoverRequest: [UInt8]? = nil) -> NfcEngagement? {
        let records = Ndef.decodeMessage(handoverSelect)
        guard hasHandover(records, "Hs"),
              let de = records.first(where: { $0.tnf == Ndef.tnfExternal && $0.type == deType })?.payload
        else { return nil }
        let readerUuid = handoverRequest.flatMap(parseHandoverRequest)?.centralClientUuid
        // The carrier the mdoc named for itself, if any; a UUID-less one carries no address to dial.
        guard let mdocCarrier = parseCarriers(records).first(where: { $0.serviceUuid != nil }),
              let mdocUuid = mdocCarrier.serviceUuid
        else {
            guard let readerUuid else { return nil }
            return NfcEngagement(deviceEngagement: de, serviceUuid: readerUuid, peripheralServerMode: false)
        }
        // Supports both + we offered mdoc central client mode → take it, on the UUID that mode belongs to.
        if mdocCarrier.supportsPeripheral, mdocCarrier.supportsCentral, let readerUuid {
            return NfcEngagement(deviceEngagement: de, serviceUuid: readerUuid, peripheralServerMode: false)
        }
        // Otherwise the mdoc's own UUID applies, and peripheral server mode is the one it named exclusively.
        let peripheralServerMode = mdocCarrier.supportsPeripheral && !mdocCarrier.supportsCentral
        return NfcEngagement(deviceEngagement: de, serviceUuid: mdocUuid, peripheralServerMode: peripheralServerMode)
    }

    /// Builds the negotiated-handover Handover Request NDEF message the mdoc **reader** sends to the mdoc
    /// (§8.2.2.1): an `Hr` record (version + collision-resolution record + one Alternative Carrier) plus the
    /// BLE carrier-configuration record, and optionally a `ReaderEngagement` auxiliary record.
    /// `collisionResolution` is the 2-byte random the reader picks (NFC Forum CH); `serviceUuid` is the
    /// 16-byte big-endian BLE service UUID.
    ///
    /// **`peripheralServerMode` means the opposite thing here than in `buildHandoverSelect`.** The LE Role in a
    /// carrier-configuration record describes the *sender's* role, and §8.3.3.1.1.2 pins each message's meaning:
    /// a UUID in the Handover **Request** is "the mdoc reader supports **mdoc central client mode**", a UUID in
    /// the Handover **Select** is "the mdoc chooses **mdoc peripheral server mode**". So on this (reader) side
    /// `true` emits LE Role = Peripheral, i.e. *the reader* is the peripheral / GATT server and the mdoc is the
    /// central client — the mdoc-mode reading of the flag is inverted. `NfcHandoverRequest` exposes the same
    /// sender-relative values as its `offersMdoc…` helpers. Pass `true` unless the reader intends to be the BLE central.
    ///
    /// `alsoOfferMdocPeripheralServer` appends a second Alternative Carrier that puts the *mdoc* in the peripheral
    /// role, so an mdoc that cannot do the mode named first still has one it can take. It repeats `serviceUuid`:
    /// the reader proposes the service the mdoc will then advertise, and a carrier record with no UUID is not
    /// something implementations expect (the Multipaz test app dereferences it and dies). Carriers are listed in
    /// the reader's order of preference — mdocs seen so far take the first one they support rather than ranking
    /// them — and either reply is read the same way: a Select naming a UUID chose its own carrier, one without it
    /// took the carrier offered here.
    ///
    /// `singleCarrierBothRoles` emits the shape the spec actually describes instead: **one** BLE carrier whose
    /// LE Role says "both supported, Peripheral preferred" (0x02) — the reader would rather be the peripheral,
    /// i.e. it prefers mdoc central client mode, but will take either. §8.3.3.1.1.1 treats "or both" as a
    /// first-class answer, §8.2.2.1's carrier granularity is the *transmission technology* (BLE) rather than the
    /// role, and the Multipaz reader encodes its own offer this way. It also removes the duplicated UUID that
    /// `alsoOfferMdocPeripheralServer` has to send. Takes precedence over the two-carrier flags.
    public static func buildHandoverRequest(
        serviceUuid: [UInt8],
        collisionResolution: [UInt8],
        peripheralServerMode: Bool = true,
        readerEngagement: [UInt8]? = nil,
        alsoOfferMdocPeripheralServer: Bool = false,
        singleCarrierBothRoles: Bool = false
    ) -> [UInt8] {
        var carriers: [NdefRecord]
        if singleCarrierBothRoles {
            // Sender-relative: "I would rather be the Peripheral" is this reader asking for mdoc central client mode.
            carriers = [bleOobRecord(serviceUuid, leBothPeripheralPreferred, id: "0")]
        } else {
            carriers = [bleOobRecord(serviceUuid, peripheralServerMode ? lePeripheralOnly : leCentralOnly, id: "0")]
            if alsoOfferMdocPeripheralServer { carriers.append(bleOobRecord(serviceUuid, leCentralOnly, id: "1")) }
        }
        let auxRef = readerEngagement != nil ? "mdocreader" : nil
        let cr = NdefRecord(tnf: Ndef.tnfWellKnown, type: Array("cr".utf8), payload: collisionResolution)
        let acs = carriers.indices.map { acRecord(auxRef, carrierRef: String($0)) }
        let hr = NdefRecord(tnf: Ndef.tnfWellKnown, type: Array("Hr".utf8),
                            payload: [handoverVersion] + Ndef.encodeMessage([cr] + acs))
        var records = [hr]
        if let re = readerEngagement {
            records.append(NdefRecord(tnf: Ndef.tnfExternal, type: reType, id: Array("mdocreader".utf8), payload: re))
        }
        records.append(contentsOf: carriers)
        return Ndef.encodeMessage(records)
    }

    /// Parses a negotiated Handover Request NDEF message → every BLE carrier it offers + optional ReaderEngagement.
    public static func parseHandoverRequest(_ ndef: [UInt8]) -> NfcHandoverRequest? {
        let records = Ndef.decodeMessage(ndef)
        guard hasHandover(records, "Hr") else { return nil }
        let carriers = parseCarriers(records)
        guard !carriers.isEmpty else { return nil }
        let re = records.first(where: { $0.tnf == Ndef.tnfExternal && $0.type == reType })?.payload
        return NfcHandoverRequest(carriers: carriers, readerEngagement: re)
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

    /// An Alternative Carrier record: active carrier, its carrier-data reference, optional single aux-data reference.
    private static func acRecord(_ auxRef: String?, carrierRef: String = "0") -> NdefRecord {
        let head: [UInt8] = [0x01, UInt8(carrierRef.utf8.count)] + Array(carrierRef.utf8) // CPS=active + carrier-data-ref
        let aux: [UInt8] = auxRef.map { [0x01, UInt8($0.utf8.count)] + Array($0.utf8) } ?? [0x00]
        return NdefRecord(tnf: Ndef.tnfWellKnown, type: Array("ac".utf8), payload: head + aux)
    }

    /// BLE carrier-config record: `leRole` + the 128-bit service UUID written little-endian, under record id `id`.
    private static func bleOobRecord(_ serviceUuid: [UInt8], _ leRole: Int, id: String = "0") -> NdefRecord {
        NdefRecord(tnf: Ndef.tnfMimeMedia, type: oobMime, id: Array(id.utf8),
                   payload: [0x02, UInt8(adLeRole), UInt8(leRole), 0x11, UInt8(adUuid128)] + serviceUuid.reversed())
    }

    /// Reads every BLE carrier-configuration record in the message, in the order the sender listed them (which is
    /// its order of preference). A message may carry several — one per mode, or one that names both roles — and
    /// either side has to see all of them to know what was actually offered.
    ///
    /// LE Role is mandatory (§8.3.3.1.1.2) but defaults to Peripheral-only when absent, because that is what a
    /// bare UUID means in both messages: the mdoc naming its own is peripheral server mode, and the reader naming
    /// its own is the reader being the peripheral. Unknown AD types are skipped, as the spec allows.
    private static func parseCarriers(_ records: [NdefRecord]) -> [NfcBleCarrier] {
        records.filter { $0.tnf == Ndef.tnfMimeMedia && $0.type == oobMime }.map { oob in
            var i = 0
            var leRole = 0x00
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
            return NfcBleCarrier(serviceUuid: uuid, leRole: leRole)
        }
    }
}
