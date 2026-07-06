import Crypto
import Foundation

/// COSE_Mac0 (RFC 9052 §6.2) with HMAC 256/256 — the MAC form of mdoc device authentication
/// (ISO/IEC 18013-5 §9.1.3.5, `deviceMac`). Verified with the `EMacKey` derived from the EReaderKey /
/// DeviceKey ECDH secret; the counterpart of `CoseSign1` for key-agreement device keys.
public struct CoseMac0 {
    public static let tag: UInt64 = 17
    private static let emptyMapBytes: [UInt8] = [0xA0]

    public let protectedBytes: [UInt8]
    public let unprotected: CoseHeaders
    public let payload: [UInt8]?
    public let tagValue: [UInt8]

    public init(protectedBytes: [UInt8], unprotected: CoseHeaders, payload: [UInt8]?, tagValue: [UInt8]) {
        self.protectedBytes = protectedBytes
        self.unprotected = unprotected
        self.payload = payload
        self.tagValue = tagValue
    }

    /// Verifies the HMAC-SHA256 tag over the MAC_structure with `key` (EMacKey), using `detachedPayload` if detached.
    public func verify(key: [UInt8], externalAad: [UInt8] = [], detachedPayload: [UInt8]? = nil) -> Bool {
        guard let p = payload ?? detachedPayload,
              let macStructure = try? Self.macStructure(protectedBytes: protectedBytes, externalAad: externalAad, payload: p)
        else { return false }
        let expected = Array(HMAC<SHA256>.authenticationCode(for: Data(macStructure), using: SymmetricKey(data: Data(key))))
        return expected == tagValue
    }

    public static func fromCbor(_ c: Cbor) throws -> CoseMac0 {
        let body: Cbor
        if case let .tagged(t, inner) = c {
            guard t == tag else { throw CoseError.unexpectedTag(t) }
            body = inner
        } else {
            body = c
        }
        guard case let .array(items) = body, items.count == 4 else {
            throw CoseError.malformed("COSE_Mac0 must be a 4-element array")
        }
        guard case let .bytes(prot) = items[0] else { throw CoseError.malformed("protected must be bstr") }
        guard case let .map(unp) = items[1] else { throw CoseError.malformed("unprotected must be a map") }
        let payload: [UInt8]?
        switch items[2] {
        case let .bytes(b): payload = b
        case .null: payload = nil
        default: throw CoseError.malformed("payload must be bstr or null")
        }
        guard case let .bytes(t) = items[3] else { throw CoseError.malformed("tag must be bstr") }
        return CoseMac0(protectedBytes: prot, unprotected: CoseHeaders(unp), payload: payload, tagValue: t)
    }

    /// MAC_structure (RFC 9052 §6.3), context "MAC0". An empty protected map normalizes to a zero-length bstr.
    static func macStructure(protectedBytes: [UInt8], externalAad: [UInt8], payload: [UInt8]) throws -> [UInt8] {
        let normalized = (protectedBytes.isEmpty || protectedBytes == emptyMapBytes) ? [] : protectedBytes
        return try CborEncoder.encode(.array([.text("MAC0"), .bytes(normalized), .bytes(externalAad), .bytes(payload)]))
    }
}
