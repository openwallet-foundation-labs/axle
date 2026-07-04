import CborCose
import Crypto
import Foundation
import WalletAPI
import XCTest
@testable import StatusList

final class CwtStatusListTests: XCTestCase {

    private let uri = "https://issuer.example/statuslists/cwt/1"

    private let key = P256.Signing.PrivateKey()
    private var publicKey: EcPublicKey {
        let raw = key.publicKey.rawRepresentation
        return EcPublicKey(curve: .p256, x: [UInt8](raw.prefix(32)), y: [UInt8](raw.suffix(32)))
    }
    private struct P256CoseSigner: CoseSigner {
        let algorithm: CoseAlgorithm
        let key: P256.Signing.PrivateKey
        func sign(_ toBeSigned: [UInt8]) async throws -> [UInt8] {
            [UInt8](try key.signature(for: Data(toBeSigned)).rawRepresentation)
        }
    }
    private struct TestResolver: CoseStatusKeyResolver {
        let publicKey: EcPublicKey
        func resolve(x5chain: [[UInt8]]) async throws -> EcPublicKey { publicKey }
    }
    private final class CountingTransport: HttpTransport, @unchecked Sendable {
        let body: [UInt8]; let status: Int; var calls = 0
        init(_ body: [UInt8], status: Int = 200) { self.body = body; self.status = status }
        func execute(_ request: HttpRequest) async throws -> HttpResponse {
            calls += 1
            return HttpResponse(status: status, headers: [], body: body)
        }
    }

    private func packLst(bits: Int, statuses: [Int]) throws -> [UInt8] {
        let perByte = 8 / bits
        var unpacked = [UInt8](repeating: 0, count: (statuses.count + perByte - 1) / perByte)
        for (i, s) in statuses.enumerated() { unpacked[i / perByte] |= UInt8(s << ((i % perByte) * bits)) }
        return try Zlib.deflate(unpacked)
    }

    private func cwt(bits: Int, statuses: [Int], sub: String? = nil, exp: Int64? = nil, ttl: Int64? = nil) async throws -> [UInt8] {
        var claims: [(Cbor, Cbor)] = [(.int(2), .text(sub ?? uri)), (.int(6), .int(1_700_000_000))]
        if let exp { claims.append((.int(4), .int(exp))) }
        if let ttl { claims.append((.int(65534), .int(ttl))) }
        claims.append((.int(65533), .map([(.text("bits"), .int(Int64(bits))), (.text("lst"), .bytes(try packLst(bits: bits, statuses: statuses)))])))

        let proto = CoseHeaders([(.int(1), .int(-7)), (.int(16), .text("statuslist+cwt"))])
        let unprotected = CoseHeaders([(.int(33), .array([.bytes([0x30, 0x01])]))])
        let signer = P256CoseSigner(algorithm: SigningAlgorithm.es256.coseAlgorithm, key: key)
        let cose = try await CoseSign1.sign(protected: proto, unprotected: unprotected, payload: try CborEncoder.encode(.map(claims)), signer: signer)
        return try CborEncoder.encode(cose.toCbor(tagged: false))
    }

    private func client(_ t: any HttpTransport, now: Int64 = 1_700_000_100) -> CwtStatusListClient {
        CwtStatusListClient(http: t, keyResolver: TestResolver(publicKey: publicKey), clock: { now })
    }

    func testReadsStatusesFromCwt() async throws {
        let c = client(CountingTransport(try await cwt(bits: 2, statuses: [0, 1, 2, 0])))
        let s0 = try await c.check(StatusReference(index: 0, uri: uri))
        let s1 = try await c.check(StatusReference(index: 1, uri: uri))
        let s2 = try await c.check(StatusReference(index: 2, uri: uri))
        XCTAssertEqual([.valid, .invalid, .suspended], [s0, s1, s2])
    }

    func testCwtRevocationAndCache() async throws {
        let t = CountingTransport(try await cwt(bits: 1, statuses: (0..<16).map { $0 == 5 ? 1 : 0 }, ttl: 3600))
        let c = client(t)
        let s5 = try await c.check(StatusReference(index: 5, uri: uri))
        let s4 = try await c.check(StatusReference(index: 4, uri: uri))
        XCTAssertEqual([.invalid, .valid], [s5, s4])
        XCTAssertEqual(1, t.calls, "cached CWT list fetched once")
    }

    func testTamperedCwtRejected() async throws {
        var bytes = try await cwt(bits: 1, statuses: [Int](repeating: 0, count: 16))
        bytes[bytes.count - 1] = bytes[bytes.count - 1] &+ 1
        do { _ = try await client(CountingTransport(bytes)).check(StatusReference(index: 0, uri: uri)); XCTFail("should reject") } catch {}
    }

    func testCwtSubMismatchRejected() async throws {
        let c = client(CountingTransport(try await cwt(bits: 1, statuses: [Int](repeating: 0, count: 16), sub: "https://evil.example/list")))
        do { _ = try await c.check(StatusReference(index: 0, uri: uri)); XCTFail("should reject") } catch is StatusListError {}
    }

    func testCwtExpiredRejected() async throws {
        let c = client(CountingTransport(try await cwt(bits: 1, statuses: [Int](repeating: 0, count: 16), exp: 1_700_000_050)), now: 1_700_000_100)
        do { _ = try await c.check(StatusReference(index: 0, uri: uri)); XCTFail("should reject") } catch is StatusListError {}
    }

    func testReferenceFromMdocCborStatus() throws {
        let status = Cbor.map([(.text("status_list"), .map([(.text("idx"), .int(99)), (.text("uri"), .text(uri))]))])
        let ref = StatusReference.fromCbor(status)!
        XCTAssertEqual(99, ref.index)
        XCTAssertEqual(uri, ref.uri)
    }
}
