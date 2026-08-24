import Foundation
import WalletAPI
import XCTest
@testable import OpenID4VP

/// OpenID4VP 1.0 §5.9.2 — Client Identifier Prefix parsing.
///
/// The prefix is the part before the first `:`, but only when it is one of the values §5.9.3 defines;
/// "if a `:` character is not present in the Client Identifier, the Wallet MUST treat the Client Identifier
/// as referencing a pre-registered client", and a pre-registered identifier "MUST NOT contain a `:` character
/// preceded immediately by a supported Client Identifier Prefix value". So an unrecognised head is not a
/// prefix — a bare Redirect URI (`https://rp.example/cb`) is a pre-registered identifier, not `https:`.
final class ClientIdPrefixTests: XCTestCase {

    private struct DeadTransport: HttpTransport {
        func execute(_ request: HttpRequest) async throws -> HttpResponse {
            HttpResponse(status: 500, headers: [], body: [])
        }
    }

    private func enc(_ s: String) -> String { s.addingPercentEncoding(withAllowedCharacters: .alphanumerics) ?? s }

    /// An unsigned request, so the prefix is read straight off the query `client_id` with no trust verifier.
    private func schemeOf(_ clientId: String) async throws -> String {
        let dcql = #"{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:eudi:pid:1"]},"claims":[{"path":["family_name"]}]}]}"#
        let uri = "openid4vp://?client_id=\(enc(clientId))&nonce=n1&response_mode=direct_post"
            + "&response_uri=\(enc("https://rp.example/response"))&dcql_query=\(enc(dcql))"
        let resolver = AuthorizationRequestResolver(http: DeadTransport())
        return try await resolver.resolve(uri).verifier.clientIdScheme
    }

    func testReadsEveryPrefixDefinedBy593() async throws {
        let cases = [
            ("x509_san_dns:rp.example", "x509_san_dns"),
            ("x509_hash:Uvo3HtuIxuhC92rShpgqcT3YXwrqRxWEviRiA0OZszk", "x509_hash"),
            // the fixture posts to https://rp.example/response, which §5.9.3 requires this identifier to name
            ("redirect_uri:https://rp.example/response", "redirect_uri"),
            ("openid_federation:https://rp.example", "openid_federation"),
            ("decentralized_identifier:did:example:123", "decentralized_identifier"),
            ("verifier_attestation:rp.example", "verifier_attestation"),
        ]
        for (clientId, expected) in cases {
            let actual = try await schemeOf(clientId)
            XCTAssertEqual(actual, expected, "client_id '\(clientId)'")
        }
    }

    /// No `:` at all → pre-registered (§5.9.2). This is the shape the live mdoc.online verifier sends.
    func testTreatsAnUnprefixedIdentifierAsPreRegistered() async throws {
        let actual = try await schemeOf("rp.example")
        XCTAssertEqual(actual, "pre-registered")
    }

    /// A `:` whose head is not a defined prefix is part of the identifier, not a prefix. Splitting blindly
    /// turned a bare Redirect URI into the non-existent prefix `https`, which then reached the trust verifier.
    func testTreatsAnUnknownHeadAsPartOfAPreRegisteredIdentifier() async throws {
        for clientId in ["https://rp.example/cb", "urn:example:rp", "x509_san_uri:https://rp.example"] {
            let actual = try await schemeOf(clientId)
            XCTAssertEqual(actual, "pre-registered", "client_id '\(clientId)'")
        }
    }

    // MARK: - §5.9.3 `redirect_uri` prefix

    private func unsigned(_ clientId: String, _ responseMode: String, _ endpointParam: String?, _ endpoint: String?) -> String {
        let dcql = #"{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:eudi:pid:1"]},"claims":[{"path":["family_name"]}]}]}"#
        let ep = (endpointParam != nil && endpoint != nil) ? "&\(endpointParam!)=\(enc(endpoint!))" : ""
        return "openid4vp://?client_id=\(enc(clientId))&nonce=n1&response_mode=\(responseMode)\(ep)&dcql_query=\(enc(dcql))"
    }

    private func resolve(_ uri: String) async throws -> ResolvedRequest {
        try await AuthorizationRequestResolver(http: DeadTransport()).resolve(uri)
    }

    /// Under `direct_post` the identifier is the Response URI; a matching `response_uri` is accepted.
    func testAcceptsAResponseUriThatMatchesTheIdentifier() async throws {
        let r = try await resolve(unsigned("redirect_uri:https://rp.example/cb", "direct_post", "response_uri", "https://rp.example/cb"))
        XCTAssertEqual(r.responseUri, "https://rp.example/cb")
    }

    /// A request may not name one Verifier and deliver the presentation to another endpoint.
    func testRejectsAResponseUriThatDiffersFromTheIdentifier() async {
        do {
            _ = try await resolve(unsigned("redirect_uri:https://rp.example/cb", "direct_post", "response_uri", "https://attacker.example/cb"))
            XCTFail("expected a mismatched response_uri to be rejected")
        } catch {}
    }

    /// §5.9.3: the Verifier "MAY omit" the parameter — the Client Identifier then supplies the endpoint.
    func testDerivesTheEndpointWhenTheParameterIsOmitted() async throws {
        let r = try await resolve(unsigned("redirect_uri:https://rp.example/cb", "direct_post", nil, nil))
        XCTAssertEqual(r.responseUri, "https://rp.example/cb")
    }

    /// §5.9.3: "Requests using the `redirect_uri` Client Identifier Prefix cannot be signed because there is no
    /// method for the Wallet to obtain a trusted key for verification."
    func testRejectsASignedRequestUnderTheRedirectUriPrefix() async {
        let cid = enc("redirect_uri:https://rp.example/cb")
        let jws = enc("e30.e30.c2ln") // never parsed — the prefix is rejected before the JWS is touched
        for uri in ["openid4vp://?client_id=\(cid)&request=\(jws)",
                    "openid4vp://?client_id=\(cid)&request_uri=\(enc("https://rp.example/req"))"] {
            do {
                _ = try await resolve(uri)
                XCTFail("expected a signed redirect_uri request to be rejected: \(uri)")
            } catch {}
        }
    }
}
