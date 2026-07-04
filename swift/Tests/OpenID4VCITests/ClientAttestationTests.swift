import Foundation
import SdJwt
import WalletAPI
import WalletTestKit
import XCTest
@testable import OpenID4VCI

/// HAIP attestation-based client authentication: PAR + token requests carry the client attestation.
final class ClientAttestationTests: XCTestCase {

    private let now: Int64 = 1_700_000_000

    private actor Capturing: HttpTransport {
        let delegate: any HttpTransport
        var requests: [HttpRequest] = []
        init(_ delegate: any HttpTransport) { self.delegate = delegate }
        func execute(_ request: HttpRequest) async throws -> HttpResponse {
            requests.append(request)
            return try await delegate.execute(request)
        }
    }

    private struct TestRng: Rng {
        func nextBytes(_ size: Int) -> [UInt8] { (0..<size).map { UInt8(($0 + 1) & 0xff) } }
    }

    private struct FakeProvider: WalletAttestationProvider {
        func walletAttestation(keyInfo: KeyInfo) async throws -> String { "eyJ.attestation.jwt" }
        func keyAttestation(keys: [KeyInfo], nonce: String?) async throws -> String { "eyJ.key.jwt" }
    }

    private func field(_ v: JsonValue, _ k: String) -> JsonValue? {
        if case let .obj(o) = v { return o.first { $0.0 == k }?.1 }
        return nil
    }
    private func strv(_ v: JsonValue, _ k: String) -> String? {
        if case let .str(s)? = field(v, k) { return s }
        return nil
    }
    private func header(_ request: HttpRequest, _ name: String) -> String? {
        request.headers.first { $0.0 == name }?.1
    }

    func testClientAttestationOnParAndToken() async throws {
        let area = SoftwareSecureArea()
        let issuerKey = try await area.createKey(spec: KeySpec(secureArea: area.id, algorithm: .es256))
        let mock = MockIssuer(area: area, issuerKey: issuerKey, now: now) // stateful — same instance for the flow
        let capturing = Capturing(mock)

        let proofKey = try await area.createKey(spec: KeySpec(secureArea: area.id, algorithm: .es256))
        let dpopKey = try await area.createKey(spec: KeySpec(secureArea: area.id, algorithm: .es256))
        let instanceKey = try await area.createKey(spec: KeySpec(secureArea: area.id, algorithm: .es256))
        let keys = IssuanceKeys(
            proofSigner: SecureAreaJwsSigner(area: area, key: proofKey.handle, algorithm: .es256), proofPublicKey: proofKey.publicKey,
            dpopSigner: SecureAreaJwsSigner(area: area, key: dpopKey.handle, algorithm: .es256), dpopPublicKey: dpopKey.publicKey
        )
        let clientAuth = try await WalletClientAuth.create(
            provider: FakeProvider(), instanceKey: instanceKey,
            instanceSigner: SecureAreaJwsSigner(area: area, key: instanceKey.handle, algorithm: .es256),
            clientId: "wallet-instance-1", rng: TestRng(), clock: { self.now }
        )
        let client = Openid4VciClient(http: capturing, rng: TestRng(), clock: { self.now }, clientAuth: clientAuth)

        let prepared = try await client.prepareAuthorizationCodeIssuance(
            credentialIssuer: "https://issuer.example", configurationId: "eu.europa.ec.eudi.pid.1", redirectUri: "wallet://cb")
        let redirect = try await mock.execute(HttpRequest(method: .get, url: prepared.authorizationUrl))
        let location = redirect.headers.first { $0.0 == "Location" }!.1
        let code = String(location.split(separator: "=")[1].split(separator: "&")[0])
        _ = try await client.finishAuthorizationCodeIssuance(prepared: prepared, authorizationCode: code, keys: keys)

        let requests = await capturing.requests
        for path in ["/par", "/token"] {
            let req = requests.last { $0.url.hasSuffix(path) }!
            XCTAssertEqual("eyJ.attestation.jwt", header(req, "OAuth-Client-Attestation"), "attestation on \(path)")
            let jws = try Jws.parse(header(req, "OAuth-Client-Attestation-PoP")!)
            XCTAssertEqual("oauth-client-attestation-pop+jwt", strv(jws.header, "typ"))
            let payload = try JsonValue.parse(try Base64Url.decodeToString(jws.payloadB64))
            XCTAssertEqual("wallet-instance-1", strv(payload, "iss"), "PoP iss on \(path)")
            XCTAssertEqual("https://issuer.example", strv(payload, "aud"), "PoP aud on \(path)")
            XCTAssertTrue(jws.verify(key: instanceKey.publicKey, expected: .es256), "PoP signature on \(path)")
        }
    }

    func testPopJwtStructure() async throws {
        let area = SoftwareSecureArea()
        let key = try await area.createKey(spec: KeySpec(secureArea: area.id, algorithm: .es256))
        let pop = ClientAttestationPop(signer: SecureAreaJwsSigner(area: area, key: key.handle, algorithm: .es256),
                                       clientId: "client-x", rng: TestRng(), now: { self.now })
        let jws = try Jws.parse(try await pop.pop(audience: "https://as.example"))
        let payload = try JsonValue.parse(try Base64Url.decodeToString(jws.payloadB64))
        XCTAssertEqual("client-x", strv(payload, "iss"))
        XCTAssertEqual("https://as.example", strv(payload, "aud"))
        if case let .numInt(exp)? = field(payload, "exp") { XCTAssertEqual(now + 300, exp) } else { XCTFail("no exp") }
        XCTAssertTrue(jws.verify(key: key.publicKey, expected: .es256))
    }
}
