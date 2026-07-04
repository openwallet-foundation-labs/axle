import Foundation

public enum CborDecodeError: Error, Equatable {
    case unexpectedEndOfInput
    case trailingBytes
    case reservedAdditionalInfo
    case unexpectedBreak
    case indefiniteNotAllowed
    case invalidChunk
    case invalidUtf8
    case duplicateMapKey
    case invalidSimpleValue
    case nestingTooDeep
    case lengthExceedsInput
    case tagWithIndefiniteArgument
}

/// CBOR decoder (RFC 8949).
///
/// `strict` = deterministic profile: rejects indefinite lengths and duplicate map keys.
/// Lenient mode accepts well-formed indefinite-length items (needed to consume third-party data
/// and the RFC 8949 Appendix A corpus).
public enum CborDecoder {

    public static func decode(_ data: [UInt8], strict: Bool = true) throws -> Cbor {
        var reader = Reader(data: data, strict: strict)
        let v = try reader.readValue()
        guard reader.pos == data.count else { throw CborDecodeError.trailingBytes }
        return v
    }

    private struct Reader {
        let data: [UInt8]
        let strict: Bool
        var pos = 0
        var depth = 0
        static let maxDepth = 512

        init(data: [UInt8], strict: Bool) {
            self.data = data
            self.strict = strict
        }

        mutating func byte() throws -> UInt8 {
            guard pos < data.count else { throw CborDecodeError.unexpectedEndOfInput }
            defer { pos += 1 }
            return data[pos]
        }

        mutating func take(_ n: Int) throws -> [UInt8] {
            guard n >= 0, pos + n <= data.count else { throw CborDecodeError.unexpectedEndOfInput }
            defer { pos += n }
            return Array(data[pos..<(pos + n)])
        }

        var remaining: UInt64 { UInt64(data.count - pos) }

        mutating func arg(_ info: UInt8) throws -> UInt64 {
            switch info {
            case ..<24:
                return UInt64(info)
            case 24:
                return UInt64(try byte())
            case 25:
                return (UInt64(try byte()) << 8) | UInt64(try byte())
            case 26:
                var r: UInt64 = 0
                for _ in 0..<4 { r = (r << 8) | UInt64(try byte()) }
                return r
            case 27:
                var r: UInt64 = 0
                for _ in 0..<8 { r = (r << 8) | UInt64(try byte()) }
                return r
            default:
                throw CborDecodeError.reservedAdditionalInfo
            }
        }

        mutating func eatBreak() -> Bool {
            if pos < data.count && data[pos] == 0xFF {
                pos += 1
                return true
            }
            return false
        }

        mutating func readValue() throws -> Cbor {
            depth += 1
            defer { depth -= 1 }
            guard depth <= Reader.maxDepth else { throw CborDecodeError.nestingTooDeep }
            let ib = try byte()
            let major = ib >> 5
            let info = ib & 0x1F
            switch major {
            case 0: return .uint(try arg(info))
            case 1: return .nint(try arg(info))
            case 2: return .bytes(try readChunks(info, major: 2))
            case 3:
                let raw = try readChunks(info, major: 3)
                guard let s = String(bytes: raw, encoding: .utf8) else { throw CborDecodeError.invalidUtf8 }
                return .text(s)
            case 4: return try readArray(info)
            case 5: return try readMap(info)
            case 6:
                guard info != 31 else { throw CborDecodeError.tagWithIndefiniteArgument }
                return .tagged(try arg(info), try readValue())
            default:
                return try readMajor7(info)
            }
        }

        mutating func readChunks(_ info: UInt8, major: UInt8) throws -> [UInt8] {
            if info != 31 {
                let len = try arg(info)
                guard len <= remaining else { throw CborDecodeError.lengthExceedsInput }
                return try take(Int(len))
            }
            guard !strict else { throw CborDecodeError.indefiniteNotAllowed }
            var out: [UInt8] = []
            while !eatBreak() {
                let ib = try byte()
                let m = ib >> 5
                let i = ib & 0x1F
                guard m == major, i != 31 else { throw CborDecodeError.invalidChunk }
                let len = try arg(i)
                guard len <= remaining else { throw CborDecodeError.lengthExceedsInput }
                out.append(contentsOf: try take(Int(len)))
            }
            return out
        }

        mutating func readArray(_ info: UInt8) throws -> Cbor {
            if info == 31 {
                guard !strict else { throw CborDecodeError.indefiniteNotAllowed }
                var items: [Cbor] = []
                while !eatBreak() { items.append(try readValue()) }
                return .array(items)
            }
            let count = try arg(info)
            guard count <= remaining else { throw CborDecodeError.lengthExceedsInput }
            var items: [Cbor] = []
            items.reserveCapacity(Int(count))
            for _ in 0..<count { items.append(try readValue()) }
            return .array(items)
        }

        mutating func readMap(_ info: UInt8) throws -> Cbor {
            var entries: [(Cbor, Cbor)] = []
            var seen = Set<[UInt8]>()

            func add(_ k: Cbor, _ v: Cbor) throws {
                if strict {
                    let canonical = try CborEncoder.encode(k)
                    guard seen.insert(canonical).inserted else { throw CborDecodeError.duplicateMapKey }
                }
                entries.append((k, v))
            }

            if info == 31 {
                guard !strict else { throw CborDecodeError.indefiniteNotAllowed }
                while !eatBreak() {
                    let k = try readValue()
                    let v = try readValue()
                    try add(k, v)
                }
                return .map(entries)
            }
            let count = try arg(info)
            guard count <= remaining else { throw CborDecodeError.lengthExceedsInput }
            entries.reserveCapacity(Int(count))
            for _ in 0..<count {
                let k = try readValue()
                let v = try readValue()
                try add(k, v)
            }
            return .map(entries)
        }

        mutating func readMajor7(_ info: UInt8) throws -> Cbor {
            switch info {
            case ..<20:
                return .simple(info)
            case 20: return .bool(false)
            case 21: return .bool(true)
            case 22: return .null
            case 23: return .undefined
            case 24:
                let s = try byte()
                // values 0..19 have one-byte forms, 20..23 are bool/null/undefined: not well-formed here
                guard s >= 24 else { throw CborDecodeError.invalidSimpleValue }
                return .simple(s)
            case 25:
                let h = (UInt16(try byte()) << 8) | UInt16(try byte())
                return .float(bits: Half.toDouble(h).bitPattern)
            case 26:
                var r: UInt32 = 0
                for _ in 0..<4 { r = (r << 8) | UInt32(try byte()) }
                return .float(bits: Double(Float(bitPattern: r)).bitPattern)
            case 27:
                var r: UInt64 = 0
                for _ in 0..<8 { r = (r << 8) | UInt64(try byte()) }
                return .float(bits: r)
            case 31:
                throw CborDecodeError.unexpectedBreak
            default:
                throw CborDecodeError.reservedAdditionalInfo
            }
        }
    }
}
