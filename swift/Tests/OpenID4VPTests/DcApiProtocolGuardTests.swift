import CborCose
import Foundation
import SdJwt
import WalletAPI
import WalletTestKit
import XCTest
@testable import OpenID4VP

/// OpenID4VP 1.0 Appendix A.1 — the Digital Credentials API exchange protocol identifier and the request it
/// announces must agree.
///
/// The platform names the protocol (`openid4vp-v1-signed` / `-unsigned` / `-multisigned`) alongside the
/// request data. Resolving on the data shape alone lets a request announced as signed be processed as an
/// unsigned one, which drops the signature *and* the `expected_origins` replay check without a word — so the
/// wallet checks the two against each other. Multi-signed (Appendix A.3.2.2, JWS JSON Serialization) is not
/// implemented and is refused by name rather than misparsed.
final class DcApiProtocolGuardTests: XCTestCase {

    private let origin = "https://verifier.example"
    private let docType = "org.iso.18013.5.1.mDL"
    private let namespace = "org.iso.18013.5.1"

    private struct NoHttp: HttpTransport {
        func execute(_ request: HttpRequest) async throws -> HttpResponse { throw VpError.responseFailed("DC API must not do HTTP") }
    }

    private func client() -> Openid4VpClient { Openid4VpClient(http: NoHttp(), clock: { 1_700_000_000 }) }

    private func claims(clientId: String? = "x509_san_dns:verifier.example", withExpectedOrigins: Bool = true) -> String {
        let cid = clientId.map { ",\"client_id\":\"\($0)\"" } ?? ""
        let origins = withExpectedOrigins ? ",\"expected_origins\":[\"\(origin)\"]" : ""
        return """
        {"response_type":"vp_token","response_mode":"dc_api","nonce":"dcapi-nonce"\(cid)\(origins),
         "dcql_query":{"credentials":[{"id":"query_0","format":"mso_mdoc","meta":{"doctype_value":"\(docType)"},
         "claims":[{"path":["\(namespace)","family_name"]}]}]}}
        """
    }

    /// A signed DC API request: `{"request": "<JWS>"}` (Appendix A.3.2.1, JWS Compact Serialization).
    private func signed(_ claimsJson: String) async throws -> String {
        "{\"request\":\"\(try await compactJws(claimsJson))\"}"
    }

    private func compactJws(_ claimsJson: String) async throws -> String {
        let area = SoftwareSecureArea()
        let key = try await area.createKey(spec: KeySpec(secureArea: area.id, algorithm: .es256))
        let header = JsonValue.obj([("alg", .str("ES256")), ("typ", .str("oauth-authz-req+jwt"))])
        let jws = try await Jws.sign(header: header, payload: [UInt8](claimsJson.utf8),
                                     signer: SecureAreaJwsSigner(area: area, key: key.handle, algorithm: .es256))
        return jws.compact()
    }

    /// A multi-signed request (Appendix A.3.2.2): the parameters live in `payload`, one signature per client_id.
    private let jwsJsonSerialization = """
    {"payload":"eyJub25jZSI6ImRjYXBpLW5vbmNlIn0",
     "signatures":[{"protected":"eyJhbGciOiJFUzI1NiJ9","signature":"c2ln"}]}
    """

    private func expectInvalidRequest(_ requestObject: String, _ protocolId: String?, _ message: String) async {
        do {
            _ = try await client().resolveDcApiRequest(requestObject, origin: origin, protocolId: protocolId)
            XCTFail(message)
        } catch VpError.invalidRequest {
        } catch {
            XCTFail("\(message) — got \(error)")
        }
    }

    private func expectUnsupported(_ requestObject: String, _ protocolId: String?, _ message: String) async {
        do {
            _ = try await client().resolveDcApiRequest(requestObject, origin: origin, protocolId: protocolId)
            XCTFail(message)
        } catch VpError.unsupported {
        } catch {
            XCTFail("\(message) — got \(error)")
        }
    }

    func testDeclaredProtocolMatchingTheRequestResolves() async throws {
        let fromSigned = try await client().resolveDcApiRequest(try await signed(claims()), origin: origin, protocolId: "openid4vp-v1-signed")
        XCTAssertEqual("x509_san_dns:verifier.example", fromSigned.clientId)
        let fromUnsigned = try await client().resolveDcApiRequest(
            claims(clientId: nil, withExpectedOrigins: false), origin: origin, protocolId: "openid4vp-v1-unsigned")
        XCTAssertEqual(origin, fromUnsigned.clientId)
    }

    /// Announced signed, delivered unsigned: resolving it would show the caller Origin as a verified verifier.
    func testUnsignedRequestDeclaredAsSignedIsRejected() async {
        await expectInvalidRequest(claims(clientId: nil, withExpectedOrigins: false), "openid4vp-v1-signed",
                                   "unsigned data under the signed protocol must be rejected")
    }

    /// Announced unsigned, delivered signed: the wallet would then have to ignore a signature it can check.
    func testSignedRequestDeclaredAsUnsignedIsRejected() async throws {
        let request = try await signed(claims())
        await expectInvalidRequest(request, "openid4vp-v1-unsigned", "signed data under the unsigned protocol must be rejected")
    }

    /// A bare JWS (no `{"request": …}` envelope) is a signed request too, and must not pass as unsigned.
    func testBareJwsDeclaredAsUnsignedIsRejected() async throws {
        let jws = try await compactJws(claims())
        await expectInvalidRequest(jws, "openid4vp-v1-unsigned", "a bare JWS must not resolve as an unsigned request")
    }

    func testMultiSignedProtocolIsRefusedByName() async {
        await expectUnsupported(jwsJsonSerialization, "openid4vp-v1-multisigned", "multi-signed requests are not supported")
    }

    /// Recognised by shape as well: without the identifier this would fail as "missing nonce" instead.
    func testJwsJsonSerializationIsRefusedWithoutTheProtocolIdentifier() async {
        await expectUnsupported(jwsJsonSerialization, nil, "a JWS JSON Serialization body must be refused as multi-signed")
        await expectUnsupported("{\"request\":\(jwsJsonSerialization)}", nil,
                                "a wrapped JWS JSON Serialization body must be refused as multi-signed")
    }

    /// An identifier OpenID4VP does not define constrains nothing: the shape stays the only signal.
    func testUnknownProtocolIdentifierFallsBackToTheShape() async throws {
        let request = try await client().resolveDcApiRequest(
            claims(clientId: nil, withExpectedOrigins: false), origin: origin, protocolId: "openid4vp")
        XCTAssertEqual(origin, request.clientId)
    }
}
