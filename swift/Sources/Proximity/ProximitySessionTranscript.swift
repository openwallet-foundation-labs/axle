import CborCose

private let tagEncodedCbor: UInt64 = 24

/// The mdoc proximity `SessionTranscript` (ISO/IEC 18013-5 §9.1.5.1):
/// `[DeviceEngagementBytes, EReaderKeyBytes, Handover]`, where the first two are `#6.24(bstr)`
/// and Handover is `null` for QR-code engagement. Also builds a minimal QR `DeviceEngagement`.
public enum ProximitySessionTranscript {

    public static func build(deviceEngagement: [UInt8], eReaderKey: EcPublicKey, handover: Cbor = .null) throws -> Cbor {
        let deviceEngagementBytes = Cbor.tagged(tagEncodedCbor, .bytes(deviceEngagement))
        let eReaderKeyBytes = Cbor.tagged(tagEncodedCbor, .bytes(try CborEncoder.encode(CoseKey.encode(eReaderKey))))
        return .array([deviceEngagementBytes, eReaderKeyBytes, handover])
    }

    /// SessionTranscript bytes fed to session-key derivation (HKDF salt = SHA-256 of these).
    public static func encode(_ sessionTranscript: Cbor) throws -> [UInt8] { try CborEncoder.encode(sessionTranscript) }
}

/// BLE connection UUIDs offered in a `DeviceEngagement`; the reader picks a mode it supports (either may be nil).
public struct BleRetrieval {
    public let peripheralServerUuid: [UInt8]?
    public let centralClientUuid: [UInt8]?
    public init(peripheralServerUuid: [UInt8]?, centralClientUuid: [UInt8]?) {
        self.peripheralServerUuid = peripheralServerUuid
        self.centralClientUuid = centralClientUuid
    }
}

/// A minimal QR-code `DeviceEngagement` (ISO/IEC 18013-5 §8.2.1.1): version + EDeviceKey.
public enum DeviceEngagement {

    public static func qr(eDeviceKey: EcPublicKey, retrievalMethods: [[UInt8]] = []) throws -> [UInt8] {
        let eDeviceKeyBytes = Cbor.tagged(tagEncodedCbor, .bytes(try CborEncoder.encode(CoseKey.encode(eDeviceKey))))
        let security = Cbor.array([.int(1), eDeviceKeyBytes]) // [cipher-suite 1, EDeviceKeyBytes]
        var entries: [(Cbor, Cbor)] = [(.int(0), .text("1.0")), (.int(1), security)]
        if !retrievalMethods.isEmpty { // DeviceRetrievalMethods (ISO 18013-5 §8.2.1.1 key 2)
            entries.append((.int(2), .array(try retrievalMethods.map { try CborDecoder.decode($0) })))
        }
        return try CborEncoder.encode(.map(entries))
    }

    /// An ISO/IEC 18013-5 §8.3.3.1.1 BLE **mdoc peripheral server mode** `DeviceRetrievalMethod`:
    /// `[2, 1, {0: true, 10: <16-byte service UUID>}]`. Advertise it in `qr` so the reader connects over BLE.
    public static func bleRetrievalMethod(peripheralServerUuid: [UInt8]? = nil, centralClientUuid: [UInt8]? = nil) throws -> [UInt8] {
        var opts: [(Cbor, Cbor)] = [
            (.int(0), .bool(peripheralServerUuid != nil)), // mdoc peripheral server mode supported
            (.int(1), .bool(centralClientUuid != nil)),    // mdoc central client mode supported
        ]
        if let p = peripheralServerUuid { opts.append((.int(10), .bytes(p))) }
        if let c = centralClientUuid { opts.append((.int(11), .bytes(c))) }
        return try CborEncoder.encode(.array([.int(2), .int(1), .map(opts)]))
    }

    /// The BLE connection UUIDs (peripheral server / central client mode) from a QR `DeviceEngagement`, or nil — reader side.
    public static func parseBle(_ engagement: [UInt8]) -> BleRetrieval? {
        guard case let .map(entries) = try? CborDecoder.decode(engagement),
              let methods = entries.first(where: { if case let .uint(k) = $0.0 { return k == 2 }; return false })?.1,
              case let .array(items) = methods else { return nil }
        for m in items {
            guard case let .array(arr) = m, arr.count >= 3,
                  case let .uint(type) = arr[0], type == 2,
                  case let .map(opts) = arr[2] else { continue }
            func uuid(_ key: UInt64) -> [UInt8]? {
                if let v = opts.first(where: { if case let .uint(k) = $0.0 { return k == key }; return false })?.1,
                   case let .bytes(b) = v { return b }
                return nil
            }
            return BleRetrieval(peripheralServerUuid: uuid(10), centralClientUuid: uuid(11))
        }
        return nil
    }

    /// Extracts the mdoc's ephemeral public key (EDeviceKey) from a QR `DeviceEngagement` — the reader side.
    public static func parseEDeviceKey(_ engagement: [UInt8]) throws -> EcPublicKey {
        guard case let .map(entries) = try CborDecoder.decode(engagement) else {
            throw ProximityError("DeviceEngagement must be a map")
        }
        guard let security = entries.first(where: { if case let .uint(k) = $0.0 { return k == 1 }; return false })?.1,
              case let .array(items) = security, items.count >= 2,
              case let .tagged(_, inner) = items[1], case let .bytes(keyBytes) = inner else {
            throw ProximityError("missing EDeviceKey")
        }
        return try CoseKey.decode(try CborDecoder.decode(keyBytes))
    }
}
