/// CBOR data model (RFC 8949).
///
/// Deterministic encoding follows the Core Deterministic Encoding Requirements (RFC 8949 §4.2.1):
/// shortest-form heads, definite lengths only, bytewise-lexicographic map key order,
/// preferred (shortest exact) float serialization, canonical NaN (0x7e00).
public indirect enum Cbor {
    /// Major type 0: unsigned integer 0...2^64-1.
    case uint(UInt64)
    /// Major type 1: negative integer; represents -1 - n, down to -2^64.
    case nint(UInt64)
    /// Major type 2: byte string.
    case bytes([UInt8])
    /// Major type 3: text string (UTF-8).
    case text(String)
    /// Major type 4: array.
    case array([Cbor])
    /// Major type 5: map. Entry order is preserved on decode; deterministic encoding sorts by key bytes.
    case map([(Cbor, Cbor)])
    /// Major type 6: tagged value.
    case tagged(UInt64, Cbor)
    /// Major type 7: simple value other than bool/null/undefined (0...19, 32...255).
    case simple(UInt8)
    case bool(Bool)
    case null
    case undefined
    /// Major type 7: float. Raw IEEE 754 double bits are kept so -0.0 and NaN compare exactly.
    case float(bits: UInt64)
}

public extension Cbor {
    static func fp(_ d: Double) -> Cbor { .float(bits: d.bitPattern) }

    /// Convenience: signed integer to uint/nint.
    static func int(_ v: Int64) -> Cbor { v >= 0 ? .uint(UInt64(v)) : .nint(UInt64(bitPattern: ~v)) }

    var doubleValue: Double? {
        if case let .float(bits) = self { return Double(bitPattern: bits) }
        return nil
    }
}

extension Cbor: Equatable {
    public static func == (lhs: Cbor, rhs: Cbor) -> Bool {
        switch (lhs, rhs) {
        case let (.uint(a), .uint(b)): return a == b
        case let (.nint(a), .nint(b)): return a == b
        case let (.bytes(a), .bytes(b)): return a == b
        case let (.text(a), .text(b)): return a == b
        case let (.array(a), .array(b)): return a == b
        case let (.map(a), .map(b)):
            guard a.count == b.count else { return false }
            for (x, y) in zip(a, b) where !(x.0 == y.0 && x.1 == y.1) { return false }
            return true
        case let (.tagged(ta, va), .tagged(tb, vb)): return ta == tb && va == vb
        case let (.simple(a), .simple(b)): return a == b
        case let (.bool(a), .bool(b)): return a == b
        case (.null, .null): return true
        case (.undefined, .undefined): return true
        case let (.float(a), .float(b)): return a == b // raw-bit equality: -0.0 != 0.0, NaN == same-NaN
        default: return false
        }
    }
}
