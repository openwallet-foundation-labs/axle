import CborCose
import Crypto
import Foundation
import OpenID4VP
import SdJwt
import WalletAPI

/// A mock OpenID4VP verifier (HttpTransport): builds a request, receives & verifies an SD-JWT VC response.
public actor MockVerifier: HttpTransport {
    public let clientId = "verifier.example"
    public let nonce = "vp-nonce-123"
    public let responseUri = "https://verifier.example/response"
    private let issuerPublic: EcPublicKey
    private let encPubJwk: JsonValue
    private let encPrivD: [UInt8]
    public private(set) var verifiedClaims: JsonValue?
    /// When true, the verifier rejects the submitted response with HTTP 400 (e.g. issuer not trusted).
    public var rejectResponse = false
    public func setRejectResponse(_ value: Bool) { rejectResponse = value }

    public init(issuerPublic: EcPublicKey) {
        self.issuerPublic = issuerPublic
        let priv = P256.KeyAgreement.PrivateKey()
        let raw = priv.publicKey.rawRepresentation
        let ec = EcPublicKey(curve: .p256, x: [UInt8](raw.prefix(32)), y: [UInt8](raw.suffix(32)))
        if case let .obj(entries) = JwkEc.toJson(ec) {
            encPubJwk = .obj(entries + [("use", .str("enc"))])
        } else {
            encPubJwk = JwkEc.toJson(ec)
        }
        encPrivD = [UInt8](priv.rawRepresentation)
    }

    public func requestUri(_ responseMode: String) -> String {
        let dcql = #"{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:eudi:pid:1"]},"claims":[{"path":["family_name"]},{"path":["given_name"]}]}]}"#
        let clientMetadata = JsonValue.obj([
            ("jwks", .obj([("keys", .arr([encPubJwk]))])),
            ("encrypted_response_enc_values_supported", .arr([.str("A256GCM")])),
        ]).serialize()
        return "openid4vp://?client_id=\(enc(clientId))&nonce=\(enc(nonce))&response_mode=\(responseMode)" +
            "&response_uri=\(enc(responseUri))&state=xyz&dcql_query=\(enc(dcql))&client_metadata=\(enc(clientMetadata))"
    }

    public func execute(_ request: HttpRequest) async throws -> HttpResponse {
        guard request.url == responseUri, request.method == .post else {
            return HttpResponse(status: 404, headers: [], body: [])
        }
        if rejectResponse {
            return HttpResponse(status: 400, headers: [], body: Array(#"{"error":"invalid_vp_token"}"#.utf8))
        }
        let bodyStr = String(bytes: request.body ?? [], encoding: .utf8) ?? ""
        var form: [String: String] = [:]
        for pair in bodyStr.split(separator: "&") {
            let kv = pair.split(separator: "=", maxSplits: 1)
            form[String(kv[0]).removingPercentEncoding ?? ""] = kv.count > 1 ? (String(kv[1]).removingPercentEncoding ?? "") : ""
        }
        let vpToken: JsonValue
        if let response = form["response"] {
            let dec = try Jwe.decryptEcdhEs(response, recipientPrivateD: encPrivD)
            vpToken = try JsonValue.parse(String(bytes: dec, encoding: .utf8)!)["vp_token"]!
        } else {
            vpToken = try JsonValue.parse(form["vp_token"]!)
        }
        guard case let .arr(items)? = vpToken["pid"], case let .str(presentation) = items[0] else {
            throw VpError.responseFailed("no pid presentation")
        }
        let verified = try SdJwtVerifier.verify(
            try SdJwt.parse(presentation), issuerKey: issuerPublic, algorithm: .es256,
            keyBinding: SdJwtVerifier.KbRequirement(audience: clientId, nonce: nonce))
        verifiedClaims = verified.claims
        return HttpResponse(status: 200, headers: [("Content-Type", "application/json")],
                            body: [UInt8](#"{"redirect_uri":"https://verifier.example/done"}"#.utf8))
    }

    private nonisolated func enc(_ s: String) -> String {
        s.addingPercentEncoding(withAllowedCharacters: .alphanumerics) ?? s
    }
}
