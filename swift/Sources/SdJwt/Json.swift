import Foundation

public struct JsonError: Error, CustomStringConvertible {
    public let description: String

    init(_ description: String) {
        self.description = description
    }
}

/// Minimal JSON model owned by the SDK. Object entries preserve insertion order and
/// the serializer is byte-stable, so both platform cores emit identical payloads —
/// the same cross-language guarantee we pin for CBOR.
public indirect enum JsonValue {
    case null
    case bool(Bool)
    case numInt(Int64)
    /// Avoid in signed payloads that must be cross-language byte-identical.
    case numDouble(Double)
    case str(String)
    case arr([JsonValue])
    case obj([(String, JsonValue)])

    public subscript(key: String) -> JsonValue? {
        if case let .obj(entries) = self {
            return entries.first { $0.0 == key }?.1
        }
        return nil
    }

    public func serialize() -> String {
        var out = ""
        write(into: &out)
        return out
    }

    private func write(into out: inout String) {
        switch self {
        case .null:
            out += "null"
        case let .bool(b):
            out += b ? "true" : "false"
        case let .numInt(n):
            out += String(n)
        case let .numDouble(d):
            out += String(d)
        case let .str(s):
            JsonValue.writeString(s, into: &out)
        case let .arr(items):
            out += "["
            for (i, v) in items.enumerated() {
                if i > 0 { out += "," }
                v.write(into: &out)
            }
            out += "]"
        case let .obj(entries):
            out += "{"
            for (i, entry) in entries.enumerated() {
                if i > 0 { out += "," }
                JsonValue.writeString(entry.0, into: &out)
                out += ":"
                entry.1.write(into: &out)
            }
            out += "}"
        }
    }

    static func writeString(_ s: String, into out: inout String) {
        out += "\""
        for scalar in s.unicodeScalars {
            switch scalar {
            case "\"": out += "\\\""
            case "\\": out += "\\\\"
            case "\n": out += "\\n"
            case "\r": out += "\\r"
            case "\t": out += "\\t"
            case "\u{08}": out += "\\b"
            case "\u{0C}": out += "\\f"
            default:
                if scalar.value < 0x20 {
                    out += String(format: "\\u%04x", scalar.value)
                } else {
                    out.unicodeScalars.append(scalar)
                }
            }
        }
        out += "\""
    }

    public static func parse(_ text: String) throws -> JsonValue {
        var parser = JsonParser(text)
        return try parser.parseDocument()
    }
}

extension JsonValue: Equatable {
    public static func == (lhs: JsonValue, rhs: JsonValue) -> Bool {
        switch (lhs, rhs) {
        case (.null, .null): return true
        case let (.bool(a), .bool(b)): return a == b
        case let (.numInt(a), .numInt(b)): return a == b
        case let (.numDouble(a), .numDouble(b)): return a == b
        case let (.str(a), .str(b)): return a == b
        case let (.arr(a), .arr(b)): return a == b
        case let (.obj(a), .obj(b)):
            guard a.count == b.count else { return false }
            for (x, y) in zip(a, b) where !(x.0 == y.0 && x.1 == y.1) { return false }
            return true
        default: return false
        }
    }
}

private struct JsonParser {
    private let chars: [Character]
    private var pos = 0
    private var depth = 0

    init(_ text: String) {
        chars = Array(text)
    }

    mutating func parseDocument() throws -> JsonValue {
        let v = try parseValue()
        skipWs()
        guard pos == chars.count else { throw JsonError("trailing content at \(pos)") }
        return v
    }

    private mutating func parseValue() throws -> JsonValue {
        depth += 1
        defer { depth -= 1 }
        guard depth <= 256 else { throw JsonError("nesting too deep") }
        skipWs()
        guard pos < chars.count else { throw JsonError("unexpected end of input") }
        switch chars[pos] {
        case "{": return try parseObject()
        case "[": return try parseArray()
        case "\"": return .str(try parseString())
        case "t": return try literal("true", .bool(true))
        case "f": return try literal("false", .bool(false))
        case "n": return try literal("null", .null)
        case let c where c == "-" || ("0"..."9").contains(c):
            return try parseNumber()
        case let c:
            throw JsonError("unexpected '\(c)' at \(pos)")
        }
    }

    private mutating func literal(_ word: String, _ value: JsonValue) throws -> JsonValue {
        for w in word {
            guard pos < chars.count, chars[pos] == w else { throw JsonError("invalid literal at \(pos)") }
            pos += 1
        }
        return value
    }

    private mutating func parseObject() throws -> JsonValue {
        pos += 1 // {
        var entries: [(String, JsonValue)] = []
        skipWs()
        if try peek() == "}" {
            pos += 1
            return .obj(entries)
        }
        while true {
            skipWs()
            guard try peek() == "\"" else { throw JsonError("expected object key at \(pos)") }
            let key = try parseString()
            skipWs()
            guard try peek() == ":" else { throw JsonError("expected ':' at \(pos)") }
            pos += 1
            entries.append((key, try parseValue()))
            skipWs()
            switch try peek() {
            case ",": pos += 1
            case "}":
                pos += 1
                return .obj(entries)
            default: throw JsonError("expected ',' or '}' at \(pos)")
            }
        }
    }

    private mutating func parseArray() throws -> JsonValue {
        pos += 1 // [
        var items: [JsonValue] = []
        skipWs()
        if try peek() == "]" {
            pos += 1
            return .arr(items)
        }
        while true {
            items.append(try parseValue())
            skipWs()
            switch try peek() {
            case ",": pos += 1
            case "]":
                pos += 1
                return .arr(items)
            default: throw JsonError("expected ',' or ']' at \(pos)")
            }
        }
    }

    private mutating func parseString() throws -> String {
        pos += 1 // "
        var units: [UInt16] = []
        while true {
            guard pos < chars.count else { throw JsonError("unterminated string") }
            let c = chars[pos]
            pos += 1
            switch c {
            case "\"":
                return String(decoding: units, as: UTF16.self)
            case "\\":
                guard pos < chars.count else { throw JsonError("unterminated escape") }
                let e = chars[pos]
                pos += 1
                switch e {
                case "\"": units.append(0x22)
                case "\\": units.append(0x5C)
                case "/": units.append(0x2F)
                case "n": units.append(0x0A)
                case "r": units.append(0x0D)
                case "t": units.append(0x09)
                case "b": units.append(0x08)
                case "f": units.append(0x0C)
                case "u":
                    guard pos + 4 <= chars.count,
                          let unit = UInt16(String(chars[pos..<(pos + 4)]), radix: 16)
                    else { throw JsonError("bad \\u escape") }
                    units.append(unit)
                    pos += 4
                default:
                    throw JsonError("invalid escape '\\\(e)'")
                }
            default:
                if let scalarValue = c.unicodeScalars.first?.value, scalarValue < 0x20 {
                    throw JsonError("unescaped control character")
                }
                units.append(contentsOf: Array(String(c).utf16))
            }
        }
    }

    private mutating func parseNumber() throws -> JsonValue {
        let start = pos
        if chars[pos] == "-" { pos += 1 }
        while pos < chars.count, chars[pos].isNumber || "eE+-.".contains(chars[pos]) {
            pos += 1
        }
        let raw = String(chars[start..<pos])
        if !raw.contains("."), !raw.contains("e"), !raw.contains("E"), let n = Int64(raw) {
            return .numInt(n)
        }
        guard let d = Double(raw) else { throw JsonError("invalid number '\(raw)'") }
        return .numDouble(d)
    }

    private func peek() throws -> Character {
        guard pos < chars.count else { throw JsonError("unexpected end of input") }
        return chars[pos]
    }

    private mutating func skipWs() {
        while pos < chars.count, chars[pos] == " " || chars[pos] == "\t" || chars[pos] == "\n" || chars[pos] == "\r" {
            pos += 1
        }
    }
}
