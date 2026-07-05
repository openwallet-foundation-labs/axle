import Foundation
import WalletAPI
import XCTest
@testable import OpenID4VP

/// OpenID4VP §5.10: request_uri may be fetched with GET (default) or POST (with wallet_metadata).
final class RequestUriPostTests: XCTestCase {

    final class StubTransport: HttpTransport, @unchecked Sendable {
        let jws: String
        var last: HttpRequest?
        init(_ jws: String) { self.jws = jws }
        func execute(_ request: HttpRequest) async throws -> HttpResponse {
            last = request
            return HttpResponse(status: 200, headers: [], body: Array(jws.utf8))
        }
    }

    private let payload = #"{"client_id":"verifier.example","nonce":"n1","response_mode":"direct_post","response_uri":"https://verifier.example/response","dcql_query":{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:eudi:pid:1"]},"claims":[{"path":["family_name"]}]}]}}"#

    private func b64(_ s: String) -> String {
        Data(s.utf8).base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
    private func compactJws() -> String { "\(b64(#"{"alg":"ES256"}"#)).\(b64(payload)).\(b64("sig"))" }
    private func enc(_ s: String) -> String { s.addingPercentEncoding(withAllowedCharacters: .alphanumerics) ?? s }

    func testFetchesRequestUriViaPostWithWalletMetadata() async throws {
        let transport = StubTransport(compactJws())
        let resolver = AuthorizationRequestResolver(http: transport, trust: nil)
        let uri = "openid4vp://?client_id=verifier.example&request_uri=\(enc("https://verifier.example/request"))&request_uri_method=post"

        let resolved = try await resolver.resolve(uri)

        XCTAssertEqual("verifier.example", resolved.clientId)
        XCTAssertEqual("n1", resolved.nonce)
        XCTAssertEqual(.post, transport.last?.method)
        let body = String(bytes: transport.last?.body ?? [], encoding: .utf8) ?? ""
        XCTAssertTrue(body.hasPrefix("wallet_metadata="), "POST body must carry wallet_metadata: \(body)")
        XCTAssertTrue(body.contains("vp_formats_supported"), "wallet_metadata should advertise formats")
        XCTAssertTrue((transport.last?.headers ?? []).contains { $0.1.contains("x-www-form-urlencoded") })
    }

    func testFetchesRequestUriViaGetByDefault() async throws {
        let transport = StubTransport(compactJws())
        let resolver = AuthorizationRequestResolver(http: transport, trust: nil)
        let uri = "openid4vp://?client_id=verifier.example&request_uri=\(enc("https://verifier.example/request"))"

        _ = try await resolver.resolve(uri)

        XCTAssertEqual(.get, transport.last?.method)
        XCTAssertNil(transport.last?.body)
    }
}
