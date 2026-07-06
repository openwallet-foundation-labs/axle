/// One NDEF record (NFC Forum NDEF spec). `tnf` is the 3-bit Type Name Format; type/id/payload are raw bytes.
public struct NdefRecord {
    public let tnf: Int
    public let type: [UInt8]
    public let id: [UInt8]
    public let payload: [UInt8]
    public init(tnf: Int, type: [UInt8], id: [UInt8] = [], payload: [UInt8]) {
        self.tnf = tnf; self.type = type; self.id = id; self.payload = payload
    }
}

/// Minimal NDEF message encoder/decoder — enough for ISO/IEC 18013-5 NFC static handover. No chunking.
public enum Ndef {
    public static let tnfWellKnown = 0x01
    public static let tnfMimeMedia = 0x02
    public static let tnfExternal = 0x04

    public static func encodeMessage(_ records: [NdefRecord]) -> [UInt8] {
        var out: [UInt8] = []
        for (i, r) in records.enumerated() { out += encodeRecord(r, first: i == 0, last: i == records.count - 1) }
        return out
    }

    public static func decodeMessage(_ bytes: [UInt8]) -> [NdefRecord] {
        var records: [NdefRecord] = []
        var i = 0
        while i < bytes.count {
            let flags = Int(bytes[i]); i += 1
            let tnf = flags & 0x07
            let sr = flags & 0x10 != 0
            let il = flags & 0x08 != 0
            let typeLen = Int(bytes[i]); i += 1
            let payloadLen: Int
            if sr {
                payloadLen = Int(bytes[i]); i += 1
            } else {
                payloadLen = (Int(bytes[i]) << 24) | (Int(bytes[i + 1]) << 16) | (Int(bytes[i + 2]) << 8) | Int(bytes[i + 3]); i += 4
            }
            let idLen = il ? Int(bytes[i]) : 0
            if il { i += 1 }
            let type = Array(bytes[i..<i + typeLen]); i += typeLen
            let id = Array(bytes[i..<i + idLen]); i += idLen
            let payload = Array(bytes[i..<i + payloadLen]); i += payloadLen
            records.append(NdefRecord(tnf: tnf, type: type, id: id, payload: payload))
            if flags & 0x40 != 0 { break } // ME (last record)
        }
        return records
    }

    private static func encodeRecord(_ r: NdefRecord, first: Bool, last: Bool) -> [UInt8] {
        let sr = r.payload.count < 256
        let il = !r.id.isEmpty
        var flags = r.tnf
        if first { flags |= 0x80 } // MB
        if last { flags |= 0x40 } // ME
        if sr { flags |= 0x10 } // SR
        if il { flags |= 0x08 } // IL
        var out: [UInt8] = [UInt8(flags), UInt8(r.type.count)]
        if sr {
            out.append(UInt8(r.payload.count))
        } else {
            let n = r.payload.count
            out += [UInt8((n >> 24) & 0xFF), UInt8((n >> 16) & 0xFF), UInt8((n >> 8) & 0xFF), UInt8(n & 0xFF)]
        }
        if il { out.append(UInt8(r.id.count)) }
        out += r.type
        if il { out += r.id }
        out += r.payload
        return out
    }
}
