/// COSE_Key for EC2 public keys (RFC 9052 §7). Used as the mdoc `deviceKey` (ISO 18013-5).
///
/// `{ 1: 2 (kty EC2), -1: crv, -2: x (bstr), -3: y (bstr) }`
public enum CoseKey {
    private static let kty: Int64 = 1
    private static let crv: Int64 = -1
    private static let xLabel: Int64 = -2
    private static let yLabel: Int64 = -3
    private static let ktyEc2: Int64 = 2

    private static func crvId(_ curve: EcCurve) -> Int64 {
        switch curve {
        case .p256: return 1
        case .p384: return 2
        case .p521: return 3
        }
    }

    private static func curve(of id: Int64) throws -> EcCurve {
        switch id {
        case 1: return .p256
        case 2: return .p384
        case 3: return .p521
        default: throw CoseError.malformed("unsupported COSE_Key curve \(id)")
        }
    }

    public static func encode(_ key: EcPublicKey) -> Cbor {
        .map([
            (.int(kty), .int(ktyEc2)),
            (.int(crv), .int(crvId(key.curve))),
            (.int(xLabel), .bytes(key.x)),
            (.int(yLabel), .bytes(key.y)),
        ])
    }

    public static func decode(_ cbor: Cbor) throws -> EcPublicKey {
        guard case let .map(entries) = cbor else { throw CoseError.malformed("COSE_Key must be a map") }
        func get(_ label: Int64) -> Cbor? { entries.first { asInt($0.0) == label }?.1 }
        guard get(kty).flatMap(asInt) == ktyEc2 else { throw CoseError.malformed("COSE_Key is not EC2") }
        guard let crvId = get(crv).flatMap(asInt) else { throw CoseError.malformed("COSE_Key missing crv") }
        guard case let .bytes(x)? = get(xLabel) else { throw CoseError.malformed("COSE_Key missing x") }
        guard case let .bytes(y)? = get(yLabel) else { throw CoseError.malformed("COSE_Key missing y") }
        return EcPublicKey(curve: try curve(of: crvId), x: x, y: y)
    }

    static func asInt(_ c: Cbor) -> Int64? {
        switch c {
        case let .uint(v): return v <= UInt64(Int64.max) ? Int64(v) : nil
        case let .nint(v): return v <= UInt64(Int64.max) ? -1 - Int64(v) : nil
        default: return nil
        }
    }
}
