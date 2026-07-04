public enum CoseError: Error {
    case malformed(String)
    case unexpectedTag(UInt64)
    case missingPayload
}

/// COSE signature algorithms (RFC 9053 §2.1).
public enum CoseAlgorithm: Int64, CaseIterable, Sendable {
    case es256 = -7
    case es384 = -35
    case es512 = -36

    public static func fromLabel(_ label: Int64) -> CoseAlgorithm? {
        CoseAlgorithm(rawValue: label)
    }
}

/// Elliptic curves used by COSE signatures in this SDK (RFC 9053 §2.1).
public enum EcCurve: Sendable {
    case p256, p384, p521

    public var coordinateSize: Int {
        switch self {
        case .p256: return 32
        case .p384: return 48
        case .p521: return 66
        }
    }
}

/// Uncompressed EC public key as big-endian coordinates.
public struct EcPublicKey: Sendable {
    public let curve: EcCurve
    public let x: [UInt8]
    public let y: [UInt8]

    public init(curve: EcCurve, x: [UInt8], y: [UInt8]) {
        precondition(x.count <= curve.coordinateSize && y.count <= curve.coordinateSize,
                     "coordinate longer than curve size")
        self.curve = curve
        self.x = x
        self.y = y
    }
}

public extension Cbor {
    var asInt64: Int64? {
        switch self {
        case let .uint(u): return u <= UInt64(Int64.max) ? Int64(u) : nil
        case let .nint(n): return n < UInt64(Int64.max) ? -1 - Int64(n) : nil
        default: return nil
        }
    }
}

/// COSE header map (RFC 9052 §3) with typed accessors for the labels the wallet uses.
public struct CoseHeaders {
    public static let labelAlg: Int64 = 1
    public static let labelKid: Int64 = 4
    public static let labelX5chain: Int64 = 33

    public let map: [(Cbor, Cbor)]

    public init(_ map: [(Cbor, Cbor)] = []) {
        self.map = map
    }

    public var isEmpty: Bool { map.isEmpty }

    private func value(_ label: Int64) -> Cbor? {
        map.first { $0.0.asInt64 == label }?.1
    }

    public var algorithm: CoseAlgorithm? {
        value(Self.labelAlg)?.asInt64.flatMap(CoseAlgorithm.fromLabel)
    }

    public var kid: [UInt8]? {
        if case let .bytes(b)? = value(Self.labelKid) { return b }
        return nil
    }

    /// x5chain (RFC 9360, label 33): single bstr or array of bstr, leaf first.
    public var x5chain: [[UInt8]]? {
        switch value(Self.labelX5chain) {
        case .none: return nil
        case let .bytes(b): return [b]
        case let .array(items):
            var out: [[UInt8]] = []
            for item in items {
                guard case let .bytes(b) = item else { return nil }
                out.append(b)
            }
            return out
        default: return nil
        }
    }

    public static func of(algorithm: CoseAlgorithm? = nil, kid: [UInt8]? = nil) -> CoseHeaders {
        var entries: [(Cbor, Cbor)] = []
        if let algorithm { entries.append((.int(labelAlg), .int(algorithm.rawValue))) }
        if let kid { entries.append((.int(labelKid), .bytes(kid))) }
        return CoseHeaders(entries)
    }

    /// Decodes serialized protected headers; empty bstr means empty map.
    public static func decode(protectedBytes: [UInt8]) throws -> CoseHeaders {
        if protectedBytes.isEmpty { return CoseHeaders() }
        guard case let .map(entries) = try CborDecoder.decode(protectedBytes) else {
            throw CoseError.malformed("protected headers must be a map")
        }
        return CoseHeaders(entries)
    }
}

/// The signer abstraction the SecureArea adapter will implement (raw r||s signatures).
public protocol CoseSigner: Sendable {
    var algorithm: CoseAlgorithm { get }
    func sign(_ toBeSigned: [UInt8]) async throws -> [UInt8]
}

/// COSE_Sign1 (RFC 9052 §4.2). `protectedBytes` preserves the exact wire bytes so
/// verification is byte-faithful even for non-canonical peers.
public struct CoseSign1 {
    public static let tag: UInt64 = 18
    private static let emptyMapBytes: [UInt8] = [0xA0]

    public let protectedBytes: [UInt8]
    public let unprotected: CoseHeaders
    public let payload: [UInt8]?
    public let signature: [UInt8]

    public init(protectedBytes: [UInt8], unprotected: CoseHeaders, payload: [UInt8]?, signature: [UInt8]) {
        self.protectedBytes = protectedBytes
        self.unprotected = unprotected
        self.payload = payload
        self.signature = signature
    }

    public func protectedHeaders() throws -> CoseHeaders {
        try CoseHeaders.decode(protectedBytes: protectedBytes)
    }

    /// alg resolution: protected first (mdoc puts it there), unprotected as fallback.
    public var algorithm: CoseAlgorithm? {
        ((try? protectedHeaders())?.algorithm) ?? unprotected.algorithm
    }

    public func toCbor(tagged: Bool = true) -> Cbor {
        let arr = Cbor.array([
            .bytes(protectedBytes),
            .map(unprotected.map),
            payload.map { Cbor.bytes($0) } ?? .null,
            .bytes(signature),
        ])
        return tagged ? .tagged(Self.tag, arr) : arr
    }

    public func encode(tagged: Bool = true) throws -> [UInt8] {
        try CborEncoder.encode(toCbor(tagged: tagged))
    }

    public func verify(
        publicKey: EcPublicKey,
        externalAad: [UInt8] = [],
        detachedPayload: [UInt8]? = nil
    ) -> Bool {
        guard let alg = algorithm, let p = payload ?? detachedPayload else { return false }
        guard let toBeSigned = try? Self.sigStructure(
            protectedBytes: protectedBytes, externalAad: externalAad, payload: p
        ) else { return false }
        return Ecdsa.verify(key: publicKey, algorithm: alg, data: toBeSigned, rawSignature: signature)
    }

    public static func decode(_ bytes: [UInt8], strict: Bool = true) throws -> CoseSign1 {
        try fromCbor(try CborDecoder.decode(bytes, strict: strict))
    }

    public static func fromCbor(_ c: Cbor) throws -> CoseSign1 {
        let body: Cbor
        if case let .tagged(t, inner) = c {
            guard t == tag else { throw CoseError.unexpectedTag(t) }
            body = inner
        } else {
            body = c
        }
        guard case let .array(items) = body, items.count == 4 else {
            throw CoseError.malformed("COSE_Sign1 must be a 4-element array")
        }
        guard case let .bytes(prot) = items[0] else { throw CoseError.malformed("protected must be bstr") }
        guard case let .map(unp) = items[1] else { throw CoseError.malformed("unprotected must be a map") }
        let payload: [UInt8]?
        switch items[2] {
        case let .bytes(b): payload = b
        case .null: payload = nil
        default: throw CoseError.malformed("payload must be bstr or null")
        }
        guard case let .bytes(sig) = items[3] else { throw CoseError.malformed("signature must be bstr") }
        return CoseSign1(protectedBytes: prot, unprotected: CoseHeaders(unp), payload: payload, signature: sig)
    }

    /// Sig_structure (RFC 9052 §4.4). An empty protected map — whether encoded as
    /// h'' or h'A0' on the wire — normalizes to a zero-length bstr (cose-wg sign-pass-01).
    public static func sigStructure(
        protectedBytes: [UInt8],
        externalAad: [UInt8],
        payload: [UInt8]
    ) throws -> [UInt8] {
        let normalized = (protectedBytes.isEmpty || protectedBytes == emptyMapBytes) ? [] : protectedBytes
        return try CborEncoder.encode(.array([
            .text("Signature1"),
            .bytes(normalized),
            .bytes(externalAad),
            .bytes(payload),
        ]))
    }

    public static func sign(
        protected: CoseHeaders,
        unprotected: CoseHeaders = CoseHeaders(),
        payload: [UInt8]?,
        externalAad: [UInt8] = [],
        detachedPayload: [UInt8]? = nil,
        signer: CoseSigner
    ) async throws -> CoseSign1 {
        let protBytes = protected.isEmpty ? [] : try CborEncoder.encode(.map(protected.map))
        guard let p = payload ?? detachedPayload else { throw CoseError.missingPayload }
        let toBeSigned = try sigStructure(protectedBytes: protBytes, externalAad: externalAad, payload: p)
        let sig = try await signer.sign(toBeSigned)
        return CoseSign1(protectedBytes: protBytes, unprotected: unprotected, payload: payload, signature: sig)
    }
}
