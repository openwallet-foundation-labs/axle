import CborCose
import Foundation
import SdJwt
import WalletAPI

/// Resolves the CWT status list signer's key from the COSE `x5chain` (leaf-first DER), validating
/// the chain to a trust anchor. Implemented by the `Trust` module — the same shape as mdoc issuer
/// trust — so chain validation is reused for CWT status lists (mdoc credentials).
public protocol CoseStatusKeyResolver: Sendable {
    func resolve(x5chain: [[UInt8]]) async throws -> EcPublicKey
}

func cborByText(_ entries: [(Cbor, Cbor)], _ name: String) -> Cbor? {
    entries.first { if case let .text(t) = $0.0 { return t == name }; return false }?.1
}

func cborByInt(_ entries: [(Cbor, Cbor)], _ label: Int64) -> Cbor? {
    entries.first { asInt64($0.0) == label }?.1
}

private func asInt64(_ c: Cbor) -> Int64? {
    switch c {
    case let .uint(v): return v <= UInt64(Int64.max) ? Int64(v) : nil
    case let .nint(v): return v <= UInt64(Int64.max) ? -1 - Int64(v) : nil
    default: return nil
    }
}

extension StatusReference {
    /// Extracts an mdoc CBOR `status = { status_list: { idx, uri } }` reference (nil if absent).
    public static func fromCbor(_ status: Cbor?) -> StatusReference? {
        guard case let .map(entries)? = status,
              case let .map(sl)? = cborByText(entries, "status_list"),
              case let .uint(idx)? = cborByText(sl, "idx"),
              case let .text(uri)? = cborByText(sl, "uri") else { return nil }
        return StatusReference(index: Int64(idx), uri: uri)
    }
}

/// Fetches, verifies, caches and reads a **CWT** Token Status List (`statuslist+cwt`, a COSE_Sign1)
/// — the CBOR sibling of `StatusListClient` used by mdoc credentials (IETF Token Status List §5.2).
/// CWT claim keys: `sub`=2, `exp`=4, `ttl`=65534, `status_list`=65533; the `status_list` value is a
/// CBOR map `{ "bits": uint, "lst": bstr }` (raw zlib bytes, not base64url).
public actor CwtStatusListClient {
    private let http: any HttpTransport
    private let keyResolver: any CoseStatusKeyResolver
    private let clock: () -> Int64
    private let defaultTtlSeconds: Int64
    private var cache: [String: (list: StatusList, expiresAt: Int64)] = [:]

    public init(
        http: any HttpTransport,
        keyResolver: any CoseStatusKeyResolver,
        clock: @escaping () -> Int64 = { Int64(Date().timeIntervalSince1970) },
        defaultTtlSeconds: Int64 = 300
    ) {
        self.http = http
        self.keyResolver = keyResolver
        self.clock = clock
        self.defaultTtlSeconds = defaultTtlSeconds
    }

    public func check(_ reference: StatusReference) async throws -> CredentialStatus {
        try await fetchList(reference.uri).statusAt(reference.index)
    }

    private func fetchList(_ uri: String) async throws -> StatusList {
        let now = clock()
        if let cached = cache[uri], cached.expiresAt > now { return cached.list }

        let resp = try await http.execute(HttpRequest(method: .get, url: uri, headers: [("Accept", "application/statuslist+cwt")], body: nil))
        guard (200...299).contains(resp.status) else { throw StatusListError("status list fetch failed: HTTP \(resp.status)") }

        let cose = try CoseSign1.fromCbor(try CborDecoder.decode(resp.body))
        let protectedHeaders = try? cose.protectedHeaders()
        if let prot = protectedHeaders, case let .text(typ)? = cborByInt(prot.map, 16), typ != "statuslist+cwt" {
            throw StatusListError("unexpected status list token typ '\(typ)'")
        }
        guard let x5chain = protectedHeaders?.x5chain ?? cose.unprotected.x5chain else {
            throw StatusListError("CWT status list has no x5chain")
        }
        let key = try await keyResolver.resolve(x5chain: x5chain) // verifies chain (throws if untrusted)
        guard cose.verify(publicKey: key) else { throw StatusListError("status list token signature invalid") }

        guard let payload = cose.payload, case let .map(claims) = try CborDecoder.decode(payload) else {
            throw StatusListError("CWT payload must be a map")
        }
        if case let .text(sub)? = cborByInt(claims, 2), sub != uri {
            throw StatusListError("status list token sub '\(sub)' does not match its URI")
        }
        var exp: Int64?
        if case let .uint(e)? = cborByInt(claims, 4) { exp = Int64(e); if Int64(e) <= now { throw StatusListError("status list token expired") } }

        guard case let .map(sl)? = cborByInt(claims, 65533) else { throw StatusListError("missing status_list (CWT claim 65533)") }
        guard case let .uint(bits)? = cborByText(sl, "bits") else { throw StatusListError("missing bits") }
        guard case let .bytes(lst)? = cborByText(sl, "lst") else { throw StatusListError("missing lst") }
        let list = try StatusList.fromBitsAndCompressed(bits: Int(bits), compressedLst: lst)

        var expiresAt = now + defaultTtlSeconds
        if case let .uint(ttl)? = cborByInt(claims, 65534) { expiresAt = now + Int64(ttl) }
        else if let exp { expiresAt = exp }
        cache[uri] = (list, expiresAt)
        return list
    }
}
