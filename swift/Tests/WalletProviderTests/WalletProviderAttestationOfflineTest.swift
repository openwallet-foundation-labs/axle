import XCTest
import WalletAPI
import SdJwt
import WalletTestKit
@testable import WalletProvider

/// Server-independent test of the reference adapter's HTTP dance — a fake `HttpTransport` canned to look
/// like the wallet-provider backend, so the sequence and payloads are verified without a running server.
final class WalletProviderAttestationOfflineTest: XCTestCase {

    private actor FakeBackend: HttpTransport {
        private(set) var requests: [HttpRequest] = []
        private var nonces = 0

        func execute(_ request: HttpRequest) async throws -> HttpResponse {
            requests.append(request)
            let json: String
            if request.url.hasSuffix("/nonce") { nonces += 1; json = "{\"nonce\":\"n\(nonces)\"}" }
            else if request.url.hasSuffix("/wallet-instances") { json = "{\"instanceId\":\"inst-1\"}" }
            else if request.url.hasSuffix("/wallet-attestation") { json = "{\"wallet_attestation\":\"header.payload.sig\"}" }
            else if request.url.hasSuffix("/key-attestation") { json = "{\"key_attestation\":\"ka.ka.ka\"}" }
            else { return HttpResponse(status: 404, headers: [], body: []) }
            return HttpResponse(status: 200, headers: [("content-type", "application/json")], body: [UInt8](json.utf8))
        }

        func paths(_ base: String) -> [String] { requests.map { String($0.url.dropFirst(base.count)) } }
        func bodyOf(_ path: String) throws -> JsonValue {
            try JsonValue.parse(String(decoding: requests.first(where: { $0.url.hasSuffix(path) })!.body!, as: UTF8.self))
        }
        func registrationCount() -> Int { requests.filter { $0.url.hasSuffix("/wallet-instances") }.count }
    }

    private func str(_ json: JsonValue?) -> String? { if case let .str(v)? = json { return v }; return nil }

    func testRegistersOnceThenFetchesWuaWithSignedPop() async throws {
        let area = SoftwareSecureArea()
        let key = try await area.createKey(spec: KeySpec(secureArea: area.id))
        let backend = FakeBackend()
        let provider = WalletProviderAttestation(
            baseUrl: "http://wp.test", http: backend, secureArea: area,
            integrity: DevIntegrityTokenProvider(), clientId: "wallet-dev", clock: { 1000 })

        let wua = try await provider.walletAttestation(keyInfo: key)
        XCTAssertEqual(wua, "header.payload.sig")

        // nonce → register → nonce → wallet-attestation
        let paths = await backend.paths("http://wp.test")
        XCTAssertEqual(paths, ["/nonce", "/wallet-instances", "/nonce", "/wallet-attestation"])

        let register = try await backend.bodyOf("/wallet-instances")
        XCTAssertEqual(str(register["integrityToken"]), "dev-integrity:n1")
        XCTAssertEqual(str(register["instanceKey"]?["x"]), Base64Url.encode(key.publicKey.x))

        let attest = try await backend.bodyOf("/wallet-attestation")
        XCTAssertEqual(str(attest["instanceId"]), "inst-1")
        XCTAssertEqual(str(attest["clientId"]), "wallet-dev")
        XCTAssertEqual(str(attest["pop"])?.split(separator: ".").count, 3)

        // A second WUA reuses the cached registration.
        _ = try await provider.walletAttestation(keyInfo: key)
        let registrations = await backend.registrationCount()
        XCTAssertEqual(registrations, 1)
    }
}
