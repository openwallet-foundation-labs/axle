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
    public static func bleRetrievalMethod(serviceUuid: [UInt8]) throws -> [UInt8] {
        try CborEncoder.encode(.array([
            .int(2), .int(1), // type 2 = BLE, version 1
            .map([(.int(0), .bool(true)), (.int(10), .bytes(serviceUuid))]),
        ]))
    }

    /// The BLE peripheral-server-mode service UUID (16 bytes) from a QR `DeviceEngagement`, or nil — the reader side.
    public static func parseBleUuid(_ engagement: [UInt8]) -> [UInt8]? {
        guard case let .map(entries) = try? CborDecoder.decode(engagement),
              let methods = entries.first(where: { if case let .uint(k) = $0.0 { return k == 2 }; return false })?.1,
              case let .array(items) = methods else { return nil }
        for m in items {
            guard case let .array(arr) = m, arr.count >= 3,
                  case let .uint(type) = arr[0], type == 2,
                  case let .map(opts) = arr[2] else { continue }
            if let uuid = opts.first(where: { if case let .uint(k) = $0.0 { return k == 10 }; return false })?.1,
               case let .bytes(b) = uuid { return b }
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
