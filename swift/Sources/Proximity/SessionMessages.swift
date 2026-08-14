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

    /// `EReaderKeyBytes = #6.24(bstr .cbor EReaderKey)` (§9.1.1.4) for a key this party generated — the one
    /// place the reader's ephemeral key is encoded, so the `SessionEstablishment` message and the
    /// SessionTranscript are guaranteed to carry identical bytes (§8.1).
    public static func eReaderKeyBytes(_ eReaderKey: EcPublicKey) throws -> [UInt8] {
        try CborEncoder.encode(.tagged(tagEncodedCbor, .bytes(try CborEncoder.encode(CoseKey.encode(eReaderKey)))))
    }

    public static func encodeEstablishment(eReaderKey: EcPublicKey, encryptedDeviceRequest: [UInt8]) throws -> [UInt8] {
        try encodeEstablishment(eReaderKeyBytes: try eReaderKeyBytes(eReaderKey),
                                encryptedDeviceRequest: encryptedDeviceRequest)
    }

    /// As above, from already-encoded `EReaderKeyBytes` — so a sender reuses the exact bytes it will bind.
    public static func encodeEstablishment(eReaderKeyBytes: [UInt8], encryptedDeviceRequest: [UInt8]) throws -> [UInt8] {
        try CborEncoder.encode(.map([
            (.text("eReaderKey"), try CborDecoder.decode(eReaderKeyBytes)),
            (.text("data"), .bytes(encryptedDeviceRequest)),
        ]))
    }

    public static func decodeEstablishment(_ bytes: [UInt8]) throws -> SessionEstablishment {
        let map = try CborDecoder.decode(bytes)
        guard case let .tagged(tag, inner)? = field(map, "eReaderKey"), case let .bytes(keyBytes) = inner else {
            throw ProximityError("missing eReaderKey")
        }
        guard tag == tagEncodedCbor else { throw ProximityError("eReaderKey must be #6.24") }
        let eReaderKey = try CoseKey.decode(try CborDecoder.decode(keyBytes))
        guard case let .bytes(data)? = field(map, "data") else { throw ProximityError("missing data") }
        // Keep the received bytestring — the COSE_Key map inside is preserved verbatim, so a peer whose key
        // ordering or optional labels differ from ours still yields the same SessionTranscript (§8.1).
        let received = try CborEncoder.encode(.tagged(tagEncodedCbor, .bytes(keyBytes)))
        return SessionEstablishment(eReaderKey: eReaderKey, eReaderKeyBytes: received, encryptedDeviceRequest: data)
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

/// A decoded `SessionEstablishment` (§9.1.1.4). `eReaderKey` is the parsed key — use it for the ECDH;
/// `eReaderKeyBytes` is the `#6.24(bstr)` **as received** — use it for the SessionTranscript, which §8.1
/// forbids re-creating from the parsed map.
public struct SessionEstablishment {
    public let eReaderKey: EcPublicKey
    public let eReaderKeyBytes: [UInt8]
    public let encryptedDeviceRequest: [UInt8]
}
