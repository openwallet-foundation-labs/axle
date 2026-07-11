import CborCose
import Foundation
import SdJwt
import WalletAPI
import WalletTestKit
import XCTest
@testable import OpenID4VP

/// OpenID4VP 1.0 Appendix A.2 — `expected_origins` on the Digital Credentials API.
///
/// A signed request object is a bearer artifact: a malicious site can replay one captured from a
/// legitimate verifier and the signature still checks out. `expected_origins` lives inside the signed
/// payload, so the wallet compares it to the platform-supplied Origin and rejects the mismatch.
/// The parameter is REQUIRED for signed requests and MUST be ignored in unsigned ones.
final class DcApiExpectedOriginsTests: XCTestCase {

    private let origin = "https://verifier.example"
    private let evilOrigin = "https://evil.example"
    private let docType = "org.iso.18013.5.1.mDL"
    private let namespace = "org.iso.18013.5.1"

    private struct NoHttp: HttpTransport {
        func execute(_ request: HttpRequest) async throws -> HttpResponse { throw VpError.responseFailed("DC API must not do HTTP") }
    }

    private func client() -> Openid4VpClient { Openid4VpClient(http: NoHttp(), clock: { 1_700_000_000 }) }

    private func claims(clientId: String? = "x509_san_dns:verifier.example", expectedOrigins: String? = nil) -> String {
        let eo = expectedOrigins ?? "[\"\(origin)\"]"
        let cid = clientId.map { ",\"client_id\":\"\($0)\"" } ?? ""
        let origins = eo == "null" ? "" : ",\"expected_origins\":\(eo)"
        return """
        {"response_type":"vp_token","response_mode":"dc_api","nonce":"dcapi-nonce"\(cid)\(origins),
         "dcql_query":{"credentials":[{"id":"query_0","format":"mso_mdoc","meta":{"doctype_value":"\(docType)"},
         "claims":[{"path":["\(namespace)","family_name"]}]}]}}
        """
    }

    /// A signed DC API request: `{"request": "<JWS>"}` (JAR), as the platform hands it to the wallet.
    private func signed(_ claimsJson: String) async throws -> String {
        let area = SoftwareSecureArea()
        let key = try await area.createKey(spec: KeySpec(secureArea: area.id, algorithm: .es256))
        let header = JsonValue.obj([("alg", .str("ES256")), ("typ", .str("oauth-authz-req+jwt"))])
        let jws = try await Jws.sign(header: header, payload: [UInt8](claimsJson.utf8),
                                     signer: SecureAreaJwsSigner(area: area, key: key.handle, algorithm: .es256))
        return "{\"request\":\"\(jws.compact())\"}"
    }

    private func expectInvalidRequest(_ requestObject: String, _ origin: String, _ message: String) async {
        do {
            _ = try await client().resolveDcApiRequest(requestObject, origin: origin)
            XCTFail(message)
        } catch VpError.invalidRequest {
        } catch {
            XCTFail("\(message) — got \(error)")
        }
    }

    func testSignedRequestWithMatchingOriginResolves() async throws {
        let request = try await client().resolveDcApiRequest(try await signed(claims()), origin: origin)
        XCTAssertEqual(origin, request.origin)
        XCTAssertEqual("x509_san_dns:verifier.example", request.clientId) // from the signed claims
    }

    /// The attack: a signed request captured from verifier.example, replayed by evil.example.
    func testSignedRequestReplayedOnAnotherOriginIsRejected() async throws {
        let stolen = try await signed(claims()) // expected_origins = [verifier.example]
        await expectInvalidRequest(stolen, evilOrigin, "replayed signed request must be rejected")
    }

    func testSignedRequestWithoutExpectedOriginsIsRejected() async throws {
        let request = try await signed(claims(expectedOrigins: "null"))
        await expectInvalidRequest(request, origin, "signed request without expected_origins must be rejected")
    }

    func testSignedRequestWithEmptyExpectedOriginsIsRejected() async throws {
        let request = try await signed(claims(expectedOrigins: "[]"))
        await expectInvalidRequest(request, origin, "empty expected_origins must be rejected")
    }

    func testSignedRequestMatchesAnyListedOrigin() async throws {
        let many = claims(expectedOrigins: "[\"https://other.example\",\"\(origin)\"]")
        let request = try await client().resolveDcApiRequest(try await signed(many), origin: origin)
        XCTAssertEqual(origin, request.origin)
    }

    /// Appendix A.2: client_id MUST be present in a signed request — it selects the Client Identifier Prefix.
    func testSignedRequestWithoutClientIdIsRejected() async throws {
        let request = try await signed(claims(clientId: nil))
        await expectInvalidRequest(request, origin, "signed request without client_id must be rejected")
    }

    /// Unsigned: the Origin is the identity, so a `client_id` in the payload MUST be ignored (anti-spoofing).
    func testUnsignedRequestIgnoresClientId() async throws {
        let unsigned = claims(clientId: "x509_san_dns:bank.example", expectedOrigins: "null")
        let request = try await client().resolveDcApiRequest(unsigned, origin: origin)
        XCTAssertEqual(origin, request.clientId)
        XCTAssertEqual("origin", request.verifier.clientIdScheme)
        XCTAssertFalse(request.verifier.trusted)
    }

    /// Unsigned: `expected_origins` MUST be ignored even when it contradicts the actual Origin.
    func testUnsignedRequestIgnoresExpectedOrigins() async throws {
        let unsigned = claims(clientId: nil, expectedOrigins: "[\"https://somewhere.else\"]")
        let request = try await client().resolveDcApiRequest(unsigned, origin: origin)
        XCTAssertEqual(origin, request.origin)
        XCTAssertEqual(origin, request.clientId)
    }

    /// 18013-7 C.5: the Origin binds the presentation, so a blank/whitespace Origin is rejected outright.
    func testBlankOriginIsRejected() async throws {
        let unsigned = claims(clientId: nil, expectedOrigins: nil)
        await expectInvalidRequest(unsigned, "", "blank origin must be rejected")
        await expectInvalidRequest(unsigned, "   ", "whitespace origin must be rejected")
    }
}
