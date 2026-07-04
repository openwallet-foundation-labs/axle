import XCTest
@testable import CborCose

final class DeterministicTests: XCTestCase {

    private func enc(_ v: Cbor, _ order: MapKeyOrder = .bytewise8949) throws -> String {
        toHex(try CborEncoder.encode(v, mapOrder: order))
    }

    func testRfc8949MapKeySortExample() throws {
        // RFC 8949 §4.2.1 example key order: 10, 100, -1, "z", "aa", [100], false
        let entries: [(Cbor, Cbor)] = [
            (.text("aa"), .int(0)),
            (.bool(false), .int(0)),
            (.array([.int(100)]), .int(0)),
            (.int(-1), .int(0)),
            (.text("z"), .int(0)),
            (.int(100), .int(0)),
            (.int(10), .int(0)),
        ]
        XCTAssertEqual("a70a001864002000617a006261610081186400f400", try enc(.map(entries)))
    }

    func testShortestIntegerHeads() throws {
        XCTAssertEqual("00", try enc(.int(0)))
        XCTAssertEqual("17", try enc(.int(23)))
        XCTAssertEqual("1818", try enc(.int(24)))
        XCTAssertEqual("18ff", try enc(.int(255)))
        XCTAssertEqual("190100", try enc(.int(256)))
        XCTAssertEqual("19ffff", try enc(.int(65535)))
        XCTAssertEqual("1a00010000", try enc(.int(65536)))
        XCTAssertEqual("1affffffff", try enc(.int(4294967295)))
        XCTAssertEqual("1b0000000100000000", try enc(.int(4294967296)))
        XCTAssertEqual("1bffffffffffffffff", try enc(.uint(UInt64.max)))
    }

    func testNegativeIntegers() throws {
        XCTAssertEqual("20", try enc(.int(-1)))
        XCTAssertEqual("37", try enc(.int(-24)))
        XCTAssertEqual("3818", try enc(.int(-25)))
        XCTAssertEqual("38ff", try enc(.int(-256)))
        XCTAssertEqual("390100", try enc(.int(-257)))
        XCTAssertEqual("3bffffffffffffffff", try enc(.nint(UInt64.max))) // -2^64
    }

    func testFloatPreferredSerialization() throws {
        let cases: [(Double, String)] = [
            (0.0, "f90000"),
            (-0.0, "f98000"),
            (1.0, "f93c00"),
            (1.5, "f93e00"),
            (65504.0, "f97bff"),
            (5.960464477539063e-8, "f90001"),   // smallest subnormal half
            (6.103515625e-5, "f90400"),         // smallest normal half
            (100000.0, "fa47c35000"),
            (3.4028234663852886e38, "fa7f7fffff"),
            (1.1, "fb3ff199999999999a"),
            (1.0e300, "fb7e37e43c8800759c"),
            (-4.0, "f9c400"),
            (.infinity, "f97c00"),
            (-.infinity, "f9fc00"),
        ]
        for (d, hex) in cases {
            XCTAssertEqual(hex, try enc(.fp(d)), "for \(d)")
        }
        XCTAssertEqual("f97e00", try enc(.fp(.nan)), "NaN must canonicalize")
        XCTAssertEqual(
            "f97e00",
            try enc(.float(bits: 0x7FF8_0000_0000_0001)),
            "NaN payload must canonicalize"
        )
    }

    func testStrictRejectsIndefiniteLengths() {
        for hex in [
            "5f42010243030405ff",         // indefinite bytes
            "7f657374726561646d696e67ff", // indefinite text
            "9fff",                       // indefinite array
            "bf61610161629f0203ffff",     // indefinite map
        ] {
            XCTAssertThrowsError(try CborDecoder.decode(hexToBytes(hex), strict: true), hex)
        }
    }

    func testLenientDecodesIndefiniteLengths() throws {
        let v = try CborDecoder.decode(hexToBytes("9f018202039f0405ffff"), strict: false)
        XCTAssertEqual(
            Cbor.array([.int(1), .array([.int(2), .int(3)]), .array([.int(4), .int(5)])]),
            v
        )
    }

    func testStrictRejectsDuplicateMapKeys() {
        XCTAssertThrowsError(try CborDecoder.decode(hexToBytes("a201000100"), strict: true)) { error in
            XCTAssertEqual(error as? CborDecodeError, .duplicateMapKey)
        }
    }

    func testEncoderRejectsDuplicateMapKeys() {
        XCTAssertThrowsError(try CborEncoder.encode(.map([(.int(1), .int(0)), (.int(1), .int(2))]))) { error in
            XCTAssertEqual(error as? CborEncodeError, .duplicateMapKey)
        }
    }

    func testInvalidTwoByteSimpleRejected() {
        XCTAssertThrowsError(try CborDecoder.decode(hexToBytes("f814"))) { error in
            XCTAssertEqual(error as? CborDecodeError, .invalidSimpleValue)
        }
    }

    func testTrailingBytesRejected() {
        XCTAssertThrowsError(try CborDecoder.decode(hexToBytes("0000"))) { error in
            XCTAssertEqual(error as? CborDecodeError, .trailingBytes)
        }
    }

    func testInvalidUtf8Rejected() {
        XCTAssertThrowsError(try CborDecoder.decode(hexToBytes("62c328"))) { error in
            XCTAssertEqual(error as? CborDecodeError, .invalidUtf8)
        }
    }

    func testLengthFirstOrderOption() throws {
        // keys: -1 (0x20, len 1), 100 (0x1864, len 2), "a" (0x6161, len 2)
        let entries: [(Cbor, Cbor)] = [
            (.text("a"), .int(0)),
            (.int(-1), .int(0)),
            (.int(100), .int(0)),
        ]
        // RFC 8949 bytewise: 0x1864 < 0x20 < 0x6161
        XCTAssertEqual("a31864002000616100", try enc(.map(entries)))
        // RFC 7049 length-first: 0x20 < 0x1864 < 0x6161
        XCTAssertEqual("a32000186400616100", try enc(.map(entries), .lengthFirst7049))
    }
}
