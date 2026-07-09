import CborCose
import Foundation

/// ISO/IEC 18013-5 device-retrieval message framing (§9.1.1):
///  - `SessionEstablishment = {"eReaderKey": EReaderKeyBytes, "data": <encrypted DeviceRequest>}`
///  - `SessionData = {"data": <encrypted DeviceResponse>, "status": uint?}`
///
/// The encrypted `data` payloads are produced/consumed by `SessionEncryption`; this only wraps them.
public enum SessionMessages {
    private static let tagEncodedCbor: UInt64 = 24

    /// SessionData status codes (ISO 18013-5 Table 20). A status message must not also carry `data`.
    public enum Status {
        public static let sessionEncryptionError: Int64 = 10
        public static let cborDecodingError: Int64 = 11
        public static let sessionTermination: Int64 = 20
    }

    public static func encodeEstablishment(eReaderKey: EcPublicKey, encryptedDeviceRequest: [UInt8]) throws -> [UInt8] {
        let eReaderKeyBytes = Cbor.tagged(tagEncodedCbor, .bytes(try CborEncoder.encode(CoseKey.encode(eReaderKey))))
        return try CborEncoder.encode(.map([
            (.text("eReaderKey"), eReaderKeyBytes),
            (.text("data"), .bytes(encryptedDeviceRequest)),
        ]))
    }

    public static func decodeEstablishment(_ bytes: [UInt8]) throws -> SessionEstablishment {
        let map = try CborDecoder.decode(bytes)
        guard case let .tagged(_, inner)? = field(map, "eReaderKey"), case let .bytes(keyBytes) = inner else {
            throw ProximityError("missing eReaderKey")
        }
        let eReaderKey = try CoseKey.decode(try CborDecoder.decode(keyBytes))
        guard case let .bytes(data)? = field(map, "data") else { throw ProximityError("missing data") }
        return SessionEstablishment(eReaderKey: eReaderKey, encryptedDeviceRequest: data)
    }

    public static func encodeData(_ encryptedDeviceResponse: [UInt8], status: Int64? = nil) throws -> [UInt8] {
        var entries: [(Cbor, Cbor)] = [(.text("data"), .bytes(encryptedDeviceResponse))]
        if let status { entries.append((.text("status"), .int(status))) }
        return try CborEncoder.encode(.map(entries))
    }

    /// A `data`-less SessionData carrying only a status code — e.g. session termination (§9.1.1.4).
    public static func encodeStatus(_ status: Int64) throws -> [UInt8] {
        try CborEncoder.encode(.map([(.text("status"), .int(status))]))
    }

    /// A decoded SessionData frame: the encrypted `data` (absent for a status-only message) and the
    /// optional `status` code. Table 20 requires 10/11/20 to omit `data`; the receiver terminates on any.
    public static func decodeSessionData(_ bytes: [UInt8]) throws -> SessionData {
        let map = try CborDecoder.decode(bytes)
        var data: [UInt8]?
        if case let .bytes(d)? = field(map, "data") { data = d }
        var status: Int64?
        if case let .uint(s)? = field(map, "status") { status = Int64(s) }
        return SessionData(data: data, status: status)
    }

    /// The encrypted response payload, or an error when the frame is a bare status (no `data`).
    public static func decodeData(_ bytes: [UInt8]) throws -> [UInt8] {
        guard let data = try decodeSessionData(bytes).data else { throw ProximityError("SessionData has no data") }
        return data
    }

    private static func field(_ c: Cbor, _ key: String) -> Cbor? {
        guard case let .map(entries) = c else { return nil }
        return entries.first(where: { if case let .text(k) = $0.0 { return k == key }; return false })?.1
    }
}

public struct SessionData {
    public let data: [UInt8]?
    public let status: Int64?
}

public struct SessionEstablishment {
    public let eReaderKey: EcPublicKey
    public let encryptedDeviceRequest: [UInt8]
}
