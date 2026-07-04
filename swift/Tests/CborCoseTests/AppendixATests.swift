import XCTest
import Foundation
@testable import CborCose

/// Runs the official RFC 8949 Appendix A corpus (vectors/appendix_a.json from cbor/test-vectors).
final class AppendixATests: XCTestCase {

    struct MatchError: Error, CustomStringConvertible {
        let description: String
    }

    private func vectorsURL() -> URL {
        var url = URL(fileURLWithPath: #filePath)
        // swift/Tests/CborCoseTests/AppendixATests.swift -> repo root
        for _ in 0..<4 { url.deleteLastPathComponent() }
        return url.appendingPathComponent("vectors/appendix_a.json")
    }

    func testAppendixA() throws {
        let raw = try Data(contentsOf: vectorsURL())
        guard let arr = try JSONSerialization.jsonObject(with: raw) as? [[String: Any]] else {
            return XCTFail("unexpected vector file shape")
        }
        var decoded = 0
        var compared = 0
        var roundtripped = 0
        var failures: [String] = []

        for entry in arr {
            guard let hex = entry["hex"] as? String else {
                failures.append("entry without hex")
                continue
            }
            do {
                let bytes = hexToBytes(hex)
                let v = try CborDecoder.decode(bytes, strict: false)
                decoded += 1
                if let expected = entry["decoded"] {
                    try match(expected, v, hex)
                    compared += 1
                }
                if let rt = entry["roundtrip"] as? Bool, rt {
                    let re = toHex(try CborEncoder.encode(v))
                    guard re == hex else { throw MatchError(description: "roundtrip mismatch: got \(re)") }
                    roundtripped += 1
                }
            } catch {
                failures.append("\(hex): \(error)")
            }
        }

        print("appendix-a: total=\(arr.count) decoded=\(decoded) value-compared=\(compared) roundtripped=\(roundtripped)")
        XCTAssertTrue(failures.isEmpty, "failures (\(failures.count)):\n" + failures.joined(separator: "\n"))
        XCTAssertGreaterThan(arr.count, 70)
    }

    private func match(_ expected: Any, _ actual: Cbor, _ ctx: String) throws {
        switch actual {
        case let .tagged(tag, inner):
            if tag == 2, case let .bytes(b) = inner {
                try matchBigNum(expected, decimalString(b), approx: b.reduce(0.0) { $0 * 256 + Double($1) }, ctx)
            } else if tag == 3, case let .bytes(b) = inner {
                let approx = -(b.reduce(0.0) { $0 * 256 + Double($1) } + 1)
                try matchBigNum(expected, "-" + decimalString(b, addOne: true), approx: approx, ctx)
            } else {
                try match(expected, inner, ctx)
            }
        case let .uint(u):
            guard let num = expected as? NSNumber, num.uint64Value == u else {
                throw MatchError(description: "uint \(u) != \(expected) in \(ctx)")
            }
        case let .nint(n):
            guard let num = expected as? NSNumber else {
                throw MatchError(description: "nint expected number in \(ctx)")
            }
            if n <= UInt64(Int64.max) {
                let want = -1 - Int64(n)
                guard num.int64Value == want else {
                    throw MatchError(description: "nint \(want) != \(expected) in \(ctx)")
                }
            } else {
                let want = -(Double(n) + 1)
                guard num.doubleValue == want else {
                    throw MatchError(description: "big nint \(want) != \(expected) in \(ctx)")
                }
            }
        case let .text(s):
            guard let str = expected as? String, str == s else {
                throw MatchError(description: "text '\(s)' != \(expected) in \(ctx)")
            }
        case let .bool(b):
            guard let num = expected as? NSNumber, num.boolValue == b else {
                throw MatchError(description: "bool \(b) != \(expected) in \(ctx)")
            }
        case .null:
            guard expected is NSNull else {
                throw MatchError(description: "null != \(expected) in \(ctx)")
            }
        case let .float(bits):
            let d = Double(bitPattern: bits)
            guard let num = expected as? NSNumber else {
                throw MatchError(description: "float \(d) expected number in \(ctx)")
            }
            if num.doubleValue == d { return }
            // huge literals may arrive as NSDecimalNumber whose doubleValue is imprecise
            if let alt = Double("\(num)"), alt == d { return }
            throw MatchError(description: "float \(d) != \(expected) in \(ctx)")
        case let .array(items):
            guard let list = expected as? [Any], list.count == items.count else {
                throw MatchError(description: "array shape mismatch in \(ctx)")
            }
            for (e, c) in zip(list, items) { try match(e, c, ctx) }
        case let .map(entries):
            guard let obj = expected as? [String: Any], obj.count == entries.count else {
                throw MatchError(description: "map shape mismatch in \(ctx)")
            }
            for (k, v) in entries {
                let ks: String
                switch k {
                case let .text(s): ks = s
                case let .uint(u): ks = String(u)
                case let .nint(n): ks = n <= UInt64(Int64.max) ? String(-1 - Int64(n)) : "-\(n)-1"
                default: throw MatchError(description: "unexpected map key \(k) in \(ctx)")
                }
                guard let ev = obj[ks] else {
                    throw MatchError(description: "missing key '\(ks)' in \(ctx)")
                }
                try match(ev, v, ctx)
            }
        default:
            throw MatchError(description: "no decoded-comparison rule for \(actual) in \(ctx)")
        }
    }

    private func matchBigNum(_ expected: Any, _ decimal: String, approx: Double, _ ctx: String) throws {
        if "\(expected)" == decimal { return }
        if let num = expected as? NSNumber, num.doubleValue == approx { return }
        throw MatchError(description: "bignum \(decimal) != \(expected) in \(ctx)")
    }

    /// Big-endian magnitude bytes -> decimal string (no BigInt on Linux stdlib).
    private func decimalString(_ bytes: [UInt8], addOne: Bool = false) -> String {
        var digits: [Int] = [0] // little-endian decimal digits
        for b in bytes {
            var carry = Int(b)
            for i in 0..<digits.count {
                let x = digits[i] * 256 + carry
                digits[i] = x % 10
                carry = x / 10
            }
            while carry > 0 {
                digits.append(carry % 10)
                carry /= 10
            }
        }
        if addOne {
            var carry = 1
            var i = 0
            while carry > 0 {
                if i == digits.count { digits.append(0) }
                let x = digits[i] + carry
                digits[i] = x % 10
                carry = x / 10
                i += 1
            }
        }
        return String(digits.reversed().map { Character(String($0)) })
    }
}

func hexToBytes(_ s: String) -> [UInt8] {
    precondition(s.count % 2 == 0)
    var out: [UInt8] = []
    out.reserveCapacity(s.count / 2)
    var i = s.startIndex
    while i < s.endIndex {
        let j = s.index(i, offsetBy: 2)
        out.append(UInt8(s[i..<j], radix: 16)!)
        i = j
    }
    return out
}

func toHex(_ b: [UInt8]) -> String {
    b.map { String(format: "%02x", $0) }.joined()
}
