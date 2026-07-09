import Foundation
import SdJwt
import WalletAPI
import XCTest
@testable import OpenID4VP

/// OpenID4VP §8.5 Authorization Error Response: the wallet POSTs `error` / `error_description` /
/// `state` to the verifier's `response_uri`, exactly where a `vp_token` would have gone, and follows
/// any `redirect_uri` the verifier returns. Over the DC API there is no `response_uri` (§15.9.2).
final class ErrorResponseTests: XCTestCase {

    private let responseUri = "https://verifier.example/response"

    private final class CapturingTransport: HttpTransport, @unchecked Sendable {
        let body: String
        var last: HttpRequest?
        init(_ body: String = "{}") { self.body = body }
        func execute(_ request: HttpRequest) async throws -> HttpResponse {
            last = request
            return HttpResponse(status: 200, headers: [("Content-Type", "application/json")], body: Array(body.utf8))
        }
    }

    private func request(responseUri: String? = "https://verifier.example/response",
                         state: String? = "xyz",
                         origin: String? = nil) throws -> ResolvedRequest {
        let dcql = #"{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:eudi:pid:1"]},"claims":[{"path":["family_name"]}]}]}"#
        return ResolvedRequest(
            clientId: "x509_san_dns:verifier.example",
            nonce: "n1",
            state: state,
            responseMode: origin != nil ? "dc_api" : "direct_post",
            responseUri: responseUri,
            redirectUri: nil,
            dcqlQuery: try DcqlQuery.parse(try JsonValue.parse(dcql)),
            clientMetadata: nil,
            transactionData: nil,
            verifier: VerifierInfo(clientId: "x509_san_dns:verifier.example", clientIdScheme: "x509_san_dns",
                                   certificateChainDer: nil, commonName: nil, trusted: true),
            origin: origin)
    }

    private func form(_ transport: CapturingTransport) -> [String: String] {
        let body = String(bytes: transport.last?.body ?? [], encoding: .utf8) ?? ""
        var out: [String: String] = [:]
        for pair in body.split(separator: "&") {
            let kv = pair.split(separator: "=", maxSplits: 1)
            out[String(kv[0]).removingPercentEncoding ?? ""] = kv.count > 1 ? (String(kv[1]).removingPercentEncoding ?? "") : ""
        }
        return out
    }

    func testPostsErrorCodeDescriptionAndStateToResponseUri() async throws {
        let transport = CapturingTransport()
        let client = Openid4VpClient(http: transport, clock: { 0 })

        let result = try await client.reportError(try request(), code: .accessDenied, description: "the user declined")

        XCTAssertEqual(.post, transport.last?.method)
        XCTAssertEqual(responseUri, transport.last?.url)
        XCTAssertTrue((transport.last?.headers ?? []).contains { $0.1.contains("x-www-form-urlencoded") })
        let f = form(transport)
        XCTAssertEqual("access_denied", f["error"])
        XCTAssertEqual("the user declined", f["error_description"])
        XCTAssertEqual("xyz", f["state"]) // echoed so the verifier can correlate the session
        XCTAssertNil(f["vp_token"])
        XCTAssertNil(result.redirectUri)
    }

    /// §8.2: the Response URI MAY return a redirect_uri for Error Responses; the wallet MUST follow it.
    func testReturnsTheVerifiersRedirectUri() async throws {
        let transport = CapturingTransport(#"{"redirect_uri":"https://verifier.example/cancelled"}"#)
        let client = Openid4VpClient(http: transport, clock: { 0 })

        let result = try await client.reportError(try request(), code: .accessDenied)

        XCTAssertEqual("https://verifier.example/cancelled", result.redirectUri)
        XCTAssertNil(form(transport)["error_description"]) // omitted when no description is given
    }

    func testOmitsStateWhenTheRequestHadNone() async throws {
        let transport = CapturingTransport()
        _ = try await Openid4VpClient(http: transport, clock: { 0 })
            .reportError(try request(state: nil), code: .invalidRequest)
        XCTAssertNil(form(transport)["state"])
    }

    /// No response_uri over the Digital Credentials API — the error goes back to the platform (§15.9.2).
    func testRefusesToReportOverDcApi() async throws {
        let transport = CapturingTransport()
        let client = Openid4VpClient(http: transport, clock: { 0 })
        do {
            _ = try await client.reportError(try request(responseUri: nil, origin: "https://verifier.example"),
                                             code: .accessDenied)
            XCTFail("DC API must not POST an error")
        } catch VpError.unsupported {}
        XCTAssertNil(transport.last, "nothing may be sent")
    }

    /// The §8.5 taxonomy: refusals collapse to access_denied, so a verifier cannot tell "no credential" from "declined".
    func testMapsExceptionsToSpecCodes() {
        XCTAssertEqual(.invalidRequest, VpError.invalidRequest("x").errorCode)
        XCTAssertEqual(.invalidRequest, VpError.unsupported("x").errorCode)
        XCTAssertEqual(.accessDenied, VpError.queryNotSatisfiable(missing: ["pid"]).errorCode)
        XCTAssertEqual(.accessDenied, VpError.verifierNotTrusted("x").errorCode)
        XCTAssertEqual(.accessDenied, VpError.selectionIncomplete("x").errorCode)
        XCTAssertEqual("wallet_unavailable", VpErrorCode.walletUnavailable.code)
        XCTAssertEqual("invalid_request_uri_method", VpErrorCode.invalidRequestUriMethod.code)
    }
}
