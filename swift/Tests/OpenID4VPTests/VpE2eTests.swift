import CborCose
import Crypto
import Foundation
import SdJwt
import WalletAPI
import WalletTestKit
import XCTest
@testable import OpenID4VP

final class VpE2eTests: XCTestCase {

    private let now: Int64 = 1_700_000_000

    private func enc(_ s: String) -> String {
        var allowed = CharacterSet.alphanumerics
        allowed.insert(charactersIn: "-._~")
        return s.addingPercentEncoding(withAllowedCharacters: allowed) ?? s
    }

    private actor MockVerifier: HttpTransport {
        let clientId = "verifier.example"
        let nonce = "vp-nonce-123"
        let responseUri = "https://verifier.example/response"
        private let issuerPublic: EcPublicKey
        private let encPubJwk: JsonValue
        private let encPrivD: [UInt8]
        private(set) var verifiedClaims: JsonValue?

        /// The `enc` the wallet chose, read off the JWE protected header.
        private(set) var seenJweEnc: String?

        /// The `apu` the wallet sent, decoded — nil when the header was absent.
        private(set) var seenJweApu: String?

        /// The values `encrypted_response_enc_values_supported` advertises, in order.
        var encValuesSupported: [String] = ["A256GCM"]
        func setEncValuesSupported(_ values: [String]) { encValuesSupported = values }

        /// When set, client_metadata also carries JARM's singular `authorization_encrypted_response_enc`, which
        /// OpenID4VP 1.0 replaced. Verifiers still emit it, sometimes naming a different algorithm than the
        /// plural list's first entry — the wallet must ignore it.
        var authorizationEncryptedResponseEnc: String?
        func setAuthorizationEncryptedResponseEnc(_ value: String?) { authorizationEncryptedResponseEnc = value }

        init(issuerPublic: EcPublicKey) {
            self.issuerPublic = issuerPublic
            let priv = P256.KeyAgreement.PrivateKey()
            let raw = priv.publicKey.rawRepresentation
            let ec = EcPublicKey(curve: .p256, x: [UInt8](raw.prefix(32)), y: [UInt8](raw.suffix(32)))
            if case let .obj(entries) = JwkEc.toJson(ec) {
                encPubJwk = .obj(entries + [("use", .str("enc")), ("alg", .str("ECDH-ES")), ("kid", .str("verifier-enc-key-1"))])
            } else {
                encPubJwk = JwkEc.toJson(ec)
            }
            encPrivD = [UInt8](priv.rawRepresentation)
        }

        func makeRequestUri(_ responseMode: String, encode: (String) -> String) -> String {
            let dcql = #"{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:eudi:pid:1"]},"claims":[{"path":["family_name"]},{"path":["given_name"]}]}]}"#
            var metadata: [(String, JsonValue)] = [
                ("jwks", .obj([("keys", .arr([encPubJwk]))])),
                ("encrypted_response_enc_values_supported", .arr(encValuesSupported.map { .str($0) })),
            ]
            if let named = authorizationEncryptedResponseEnc {
                metadata.append(("authorization_encrypted_response_enc", .str(named)))
            }
            let clientMetadata = JsonValue.obj(metadata).serialize()
            return "openid4vp://?client_id=\(encode(clientId))&nonce=\(encode(nonce))&response_mode=\(responseMode)&response_uri=\(encode(responseUri))&state=xyz&dcql_query=\(encode(dcql))&client_metadata=\(encode(clientMetadata))"
        }

        func execute(_ request: HttpRequest) async throws -> HttpResponse {
            guard request.url == responseUri, request.method == .post else {
                return HttpResponse(status: 404, headers: [], body: [])
            }
            let bodyStr = String(bytes: request.body ?? [], encoding: .utf8) ?? ""
            var form: [String: String] = [:]
            for pair in bodyStr.split(separator: "&") {
                let kv = pair.split(separator: "=", maxSplits: 1)
                form[String(kv[0]).removingPercentEncoding ?? ""] = kv.count > 1 ? (String(kv[1]).removingPercentEncoding ?? "") : ""
            }
            let vpToken: JsonValue
            if let response = form["response"] {
                if case let .obj(hdr)? = try? JsonValue.parse(try Base64Url.decodeToString(String(response.split(separator: ".")[0]))),
                   case let .str(e)? = JsonValue.obj(hdr)["enc"] {
                    seenJweEnc = e
                    if case let .str(a)? = JsonValue.obj(hdr)["apu"] { seenJweApu = try? Base64Url.decodeToString(a) }
                }
                let dec = try Jwe.decryptEcdhEs(response, recipient: try Ecdh.PrivateKey(curve: .p256, rawD: encPrivD))
                let obj = try JsonValue.parse(String(bytes: dec, encoding: .utf8)!)
                vpToken = obj["vp_token"]!
            } else {
                vpToken = try JsonValue.parse(form["vp_token"]!)
            }
            guard case let .arr(items)? = vpToken["pid"], case let .str(presentation) = items[0] else {
                throw VpError.responseFailed("no pid presentation")
            }
            let verified = try SdJwtVerifier.verify(
                try SdJwt.parse(presentation), issuerKey: issuerPublic, algorithm: .es256,
                keyBinding: SdJwtVerifier.KbRequirement(audience: clientId, nonce: nonce, now: { 1_700_000_000 })
            )
            verifiedClaims = verified.claims
            return HttpResponse(status: 200, headers: [("Content-Type", "application/json")],
                                body: [UInt8](#"{"redirect_uri":"https://verifier.example/done"}"#.utf8))
        }
    }

    private func issuePid(_ area: SoftwareSecureArea, _ issuerKey: KeyInfo, _ holderKey: KeyInfo) async throws -> SdJwt {
        var n = 0
        let salts: () -> String = { n += 1; return "salt-\(n)" }
        return try await SdJwtIssuer(saltProvider: salts).issue(
            signer: SecureAreaJwsSigner(area: area, key: issuerKey.handle, algorithm: .es256),
            holderKey: holderKey.publicKey
        ) { b in
            b.claim("iss", "https://issuer.example")
            b.claim("vct", "urn:eudi:pid:1")
            b.sd("family_name", "Han")
            b.sd("given_name", "Jongho")
            b.sd("birthdate", "1990-05-15")
        }
    }

    /// §8.3 defines `encrypted_response_enc_values_supported` and nothing else for this, so JARM's singular
    /// `authorization_encrypted_response_enc` — which OpenID4VP 1.0 replaced — is ignored even when a Verifier
    /// sends both and they disagree. geneva2026.mdoc.online is such a Verifier: it names A256GCM there while
    /// listing `["A128GCM", "A256GCM"]` here, declaring acceptable the very value the singular field rules out.
    func testIgnoresTheLegacySingularEncAndPicksFromTheSupportedList() async throws {
        let (verifier, seen) = try await runEncFlow(supported: ["A128GCM", "A256GCM"], named: "A256GCM")
        XCTAssertEqual("A128GCM", seen, "the 1.0 list decides, not the parameter it replaced")
        let claims = await verifier.verifiedClaims!
        XCTAssertEqual(JsonValue.str("Han"), claims["family_name"])
    }

    /// An encrypted response carries an `apu`. OpenID4VP 1.0 Final binds nothing to it, but Verifiers written
    /// against the ISO 18013-7 draft — where it held the `mdocGeneratedNonce` — read the header
    /// unconditionally: geneva2026.mdoc.online answers a response without one with a 500, and accepts the
    /// identical response once it is present. It must be fresh per response, not a constant.
    func testEncryptedResponseCarriesAFreshApu() async throws {
        let area = SoftwareSecureArea()
        let issuerKey = try await area.createKey(spec: KeySpec(secureArea: area.id, algorithm: .es256))
        let holderKey = try await area.createKey(spec: KeySpec(secureArea: area.id, algorithm: .es256))
        let pid = try await issuePid(area, issuerKey, holderKey)
        let held = try HeldSdJwtVc(credentialId: "pid-1", sdJwt: pid,
                                   holderSigner: SecureAreaJwsSigner(area: area, key: holderKey.handle, algorithm: .es256))

        var seen: [String] = []
        for round in 1...2 {
            let verifier = MockVerifier(issuerPublic: issuerKey.publicKey)
            let client = Openid4VpClient(http: verifier, clock: { self.now }, rng: CountingRng(seed: UInt8(round)))
            let uri = await verifier.makeRequestUri("direct_post.jwt", encode: enc)
            let request = try await client.resolveRequest(uri)
            let matches = client.match(request, held: [held])
            _ = try await client.respond(request: request, matches: matches, selection: .auto(matches), held: [held])
            let apu = await verifier.seenJweApu
            seen.append(try XCTUnwrap(apu, "an encrypted response must carry an apu"))
        }
        XCTAssertEqual(2, Set(seen).count, "the apu is a per-response nonce, not a constant")
    }

    private struct CountingRng: Rng {
        let seed: UInt8
        func nextBytes(_ size: Int) -> [UInt8] { (0..<size).map { UInt8(($0 + Int(seed)) & 0xff) } }
    }

    /// With no `authorization_encrypted_response_enc`, the first value on the list is still what we use.
    func testFallsBackToTheSupportedListWhenNoAlgorithmIsNamed() async throws {
        let (_, seen) = try await runEncFlow(supported: ["A128GCM", "A256GCM"], named: nil)
        XCTAssertEqual("A128GCM", seen)
    }

    private func runEncFlow(supported: [String], named: String?) async throws -> (MockVerifier, String?) {
        let area = SoftwareSecureArea()
        let issuerKey = try await area.createKey(spec: KeySpec(secureArea: area.id, algorithm: .es256))
        let holderKey = try await area.createKey(spec: KeySpec(secureArea: area.id, algorithm: .es256))
        let pid = try await issuePid(area, issuerKey, holderKey)
        let held = try HeldSdJwtVc(credentialId: "pid-1", sdJwt: pid,
                                   holderSigner: SecureAreaJwsSigner(area: area, key: holderKey.handle, algorithm: .es256))

        let verifier = MockVerifier(issuerPublic: issuerKey.publicKey)
        await verifier.setEncValuesSupported(supported)
        await verifier.setAuthorizationEncryptedResponseEnc(named)
        let client = Openid4VpClient(http: verifier, clock: { self.now })

        let uri = await verifier.makeRequestUri("direct_post.jwt", encode: enc)
        let request = try await client.resolveRequest(uri)
        let matches = client.match(request, held: [held])
        _ = try await client.respond(request: request, matches: matches, selection: .auto(matches), held: [held])
        return (verifier, await verifier.seenJweEnc)
    }

    private func runFlow(_ responseMode: String) async throws {
        let area = SoftwareSecureArea()
        let issuerKey = try await area.createKey(spec: KeySpec(secureArea: area.id, algorithm: .es256))
        let holderKey = try await area.createKey(spec: KeySpec(secureArea: area.id, algorithm: .es256))
        let pid = try await issuePid(area, issuerKey, holderKey)
        let held = try HeldSdJwtVc(credentialId: "pid-1", sdJwt: pid,
                                   holderSigner: SecureAreaJwsSigner(area: area, key: holderKey.handle, algorithm: .es256))

        let verifier = MockVerifier(issuerPublic: issuerKey.publicKey)
        let client = Openid4VpClient(http: verifier, clock: { self.now })

        let uri = await verifier.makeRequestUri(responseMode, encode: enc)
        let request = try await client.resolveRequest(uri)
        XCTAssertEqual("verifier.example", request.clientId)
        let matches = client.match(request, held: [held])
        XCTAssertTrue(matches.isSatisfiable())

        let result = try await client.respond(request: request, matches: matches, selection: .auto(matches), held: [held])
        XCTAssertEqual("https://verifier.example/done", result.redirectUri)

        let claims = await verifier.verifiedClaims!
        XCTAssertEqual(JsonValue.str("Han"), claims["family_name"])
        XCTAssertEqual(JsonValue.str("Jongho"), claims["given_name"])
        XCTAssertNil(claims["birthdate"], "unrequested claim must not be disclosed")
    }

    func testDirectPostJwtEncryptedResponse() async throws { try await runFlow("direct_post.jwt") }
    func testDirectPostPlainResponse() async throws { try await runFlow("direct_post") }
}
