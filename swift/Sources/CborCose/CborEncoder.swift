/// Map key ordering profile.
///
/// `bytewise8949` is the RFC 8949 §4.2.1 core deterministic order (default).
/// `lengthFirst7049` is the legacy RFC 7049 §3.9 canonical order (length, then bytewise) —
/// kept selectable because ISO 18013-5 artifacts in the wild differ; interop to be pinned in M4.
public enum MapKeyOrder: Sendable {
    case bytewise8949
    case lengthFirst7049
}

public enum CborEncodeError: Error, Equatable {
    case duplicateMapKey
    case invalidSimpleValue(UInt8)
}

public enum CborEncoder {

    public static func encode(_ value: Cbor, mapOrder: MapKeyOrder = .bytewise8949) throws -> [UInt8] {
        var out: [UInt8] = []
        try write(value, into: &out, order: mapOrder)
        return out
    }

    private static func head(_ major: UInt8, _ arg: UInt64, into out: inout [UInt8]) {
        let mt = major << 5
        switch arg {
        case ..<24:
            out.append(mt | UInt8(arg))
        case ...0xFF:
            out.append(mt | 24); out.append(UInt8(arg))
        case ...0xFFFF:
            out.append(mt | 25); out.append(UInt8(arg >> 8)); out.append(UInt8(arg & 0xFF))
        case ...0xFFFF_FFFF:
            out.append(mt | 26)
            var s = 24
            while s >= 0 { out.append(UInt8((arg >> UInt64(s)) & 0xFF)); s -= 8 }
        default:
            out.append(mt | 27)
            var s = 56
            while s >= 0 { out.append(UInt8((arg >> UInt64(s)) & 0xFF)); s -= 8 }
        }
    }

    private static func write(_ v: Cbor, into out: inout [UInt8], order: MapKeyOrder) throws {
        switch v {
        case let .uint(u):
            head(0, u, into: &out)
        case let .nint(n):
            head(1, n, into: &out)
        case let .bytes(b):
            head(2, UInt64(b.count), into: &out); out.append(contentsOf: b)
        case let .text(s):
            let b = Array(s.utf8)
            head(3, UInt64(b.count), into: &out); out.append(contentsOf: b)
        case let .array(items):
            head(4, UInt64(items.count), into: &out)
            for i in items { try write(i, into: &out, order: order) }
        case let .map(entries):
            try writeMap(entries, into: &out, order: order)
        case let .tagged(t, inner):
            head(6, t, into: &out); try write(inner, into: &out, order: order)
        case let .simple(s):
            try writeSimple(s, into: &out)
        case let .bool(b):
            out.append(b ? 0xF5 : 0xF4)
        case .null:
            out.append(0xF6)
        case .undefined:
            out.append(0xF7)
        case let .float(bits):
            writeFloat(bits: bits, into: &out)
        }
    }

    private static func writeSimple(_ s: UInt8, into out: inout [UInt8]) throws {
        if (20...23).contains(s) { throw CborEncodeError.invalidSimpleValue(s) }
        if s < 20 { out.append(0xE0 | s) } else { out.append(0xF8); out.append(s) }
    }

    private static func writeFloat(bits: UInt64, into out: inout [UInt8]) {
        let d = Double(bitPattern: bits)
        if d.isNaN { // canonical NaN
            out.append(contentsOf: [0xF9, 0x7E, 0x00])
            return
        }
        if let h = Half.exactBits(of: d) {
            out.append(0xF9); out.append(UInt8(h >> 8)); out.append(UInt8(h & 0xFF))
            return
        }
        let f = Float(d)
        if Double(f).bitPattern == bits {
            out.append(0xFA)
            let fb = f.bitPattern
            var s = 24
            while s >= 0 { out.append(UInt8((fb >> UInt32(s)) & 0xFF)); s -= 8 }
        } else {
            out.append(0xFB)
            var s = 56
            while s >= 0 { out.append(UInt8((bits >> UInt64(s)) & 0xFF)); s -= 8 }
        }
    }

    private static func writeMap(_ entries: [(Cbor, Cbor)], into out: inout [UInt8], order: MapKeyOrder) throws {
        head(5, UInt64(entries.count), into: &out)
        var encoded: [([UInt8], Cbor)] = []
        encoded.reserveCapacity(entries.count)
        for (k, v) in entries { encoded.append((try encode(k, mapOrder: order), v)) }
        let sorted = encoded.sorted { compareKeys($0.0, $1.0, order) < 0 }
        if sorted.count > 1 {
            for i in 1..<sorted.count where sorted[i - 1].0 == sorted[i].0 {
                throw CborEncodeError.duplicateMapKey
            }
        }
        for (kb, v) in sorted {
            out.append(contentsOf: kb)
            try write(v, into: &out, order: order)
        }
    }

    private static func compareKeys(_ a: [UInt8], _ b: [UInt8], _ order: MapKeyOrder) -> Int {
        if order == .lengthFirst7049 && a.count != b.count { return a.count - b.count }
        for (x, y) in zip(a, b) where x != y { return x < y ? -1 : 1 }
        return a.count - b.count
    }
}
