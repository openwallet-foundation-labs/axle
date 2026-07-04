import CborCose
import Foundation
import SdJwt
import WalletAPI

let grantPreAuthorized = "urn:ietf:params:oauth:grant-type:pre-authorized_code"

/// Holder key material for issuance: a key-proof (bound into the credential) and a DPoP key.
public struct IssuanceKeys {
    public let proofSigner: any JwsSigner
    public let proofPublicKey: EcPublicKey
    public let dpopSigner: any JwsSigner
    public let dpopPublicKey: EcPublicKey

    public init(
        proofSigner: any JwsSigner,
        proofPublicKey: EcPublicKey,
        dpopSigner: any JwsSigner,
        dpopPublicKey: EcPublicKey
    ) {
        self.proofSigner = proofSigner
        self.proofPublicKey = proofPublicKey
        self.dpopSigner = dpopSigner
        self.dpopPublicKey = dpopPublicKey
    }
}

/// OpenID4VCI 1.0 client (HAIP subset) over the `HttpTransport` port.
///
/// Implements the pre-authorized code grant end to end: issuer + AS metadata discovery,
/// DPoP-bound token request (with one-shot DPoP-Nonce retry), c_nonce acquisition, key
/// proof of possession, and the credential request.
public struct Openid4VciClient {
    private let http: any HttpTransport
    private let rng: any Rng
    private let clock: () -> Int64
    private let clientId: String

    public init(http: any HttpTransport, rng: any Rng, clock: @escaping () -> Int64, clientId: String = "wallet-dev") {
        self.http = http
        self.rng = rng
        self.clock = clock
        self.clientId = clientId
    }

    public func loadIssuerMetadata(_ credentialIssuer: String) async throws -> CredentialIssuerMetadata {
        try await CredentialIssuerMetadata.fromObj(getJson(wellKnown(credentialIssuer, "openid-credential-issuer")))
    }

    public func loadAuthorizationServerMetadata(_ issuer: String) async throws -> AuthorizationServerMetadata {
        for suffix in ["oauth-authorization-server", "openid-configuration"] {
            let response = try await rawGet(wellKnown(issuer, suffix))
            if (200...299).contains(response.status) {
                return try AuthorizationServerMetadata.fromObj(try parseObj(response, "AS metadata"))
            }
        }
        throw VciError.metadata("no authorization server metadata at \(issuer)")
    }

    /// Runs the full pre-authorized code flow and returns the issued credential(s).
    public func issueWithPreAuthorizedCode(
        offer: CredentialOffer,
        configurationId: String,
        keys: IssuanceKeys,
        txCode: String? = nil
    ) async throws -> CredentialResponse {
        guard let preAuthCode = offer.preAuthorizedCode else {
            throw VciError.invalidOffer("offer has no pre-authorized_code grant")
        }
        if let tx = offer.txCode, txCode == nil {
            throw VciError.txCodeRequired(length: tx.length, inputMode: tx.inputMode)
        }
        guard offer.credentialConfigurationIds.contains(configurationId) else {
            throw VciError.invalidOffer("configuration '\(configurationId)' not in offer")
        }

        let issuerMeta = try await loadIssuerMetadata(offer.credentialIssuer)
        let asMeta = try await loadAuthorizationServerMetadata(issuerMeta.authorizationServers[0])
        let config = issuerMeta.credentialConfigurationsSupported[configurationId]

        let dpop = DpopProver(signer: keys.dpopSigner, publicKey: keys.dpopPublicKey, rng: rng, now: clock)

        // --- token request ---
        var form = "grant_type=\(enc(grantPreAuthorized))"
        form += "&pre-authorized_code=\(enc(preAuthCode))"
        if let txCode { form += "&tx_code=\(enc(txCode))" }
        let tokenResp = try await postFormWithDpop(asMeta.tokenEndpoint, form: form, dpop: dpop, accessToken: nil)
        let token = try TokenResponse.fromObj(try parseObj(tokenResp, "token response"))
        guard token.tokenType.lowercased() == "dpop" else {
            throw VciError.protocolError("expected DPoP token_type, got '\(token.tokenType)'")
        }

        // --- c_nonce ---
        var cNonce = token.cNonce
        if cNonce == nil, let nonceEndpoint = issuerMeta.nonceEndpoint {
            cNonce = try await fetchCNonce(nonceEndpoint)
        }

        // --- key proof + credential request ---
        let proofSigner = KeyProofSigner(signer: keys.proofSigner, publicKey: keys.proofPublicKey, now: clock)
        let proofJwt = try await proofSigner.proofJwt(credentialIssuer: issuerMeta.credentialIssuer, cNonce: cNonce, clientId: clientId)

        let requestFormat = config?.format ?? "dc+sd-jwt"
        let requestBody = JsonValue.obj([
            ("credential_configuration_id", .str(configurationId)),
            ("proofs", .obj([("jwt", .arr([.str(proofJwt)]))])),
        ]).serialize()

        let credResp = try await postJsonWithDpop(
            issuerMeta.credentialEndpoint, json: requestBody, dpop: dpop, accessToken: token.accessToken
        )
        return CredentialResponse.fromObj(try parseObj(credResp, "credential response"), requestedFormat: requestFormat)
    }

    // MARK: - HTTP helpers

    private func fetchCNonce(_ nonceEndpoint: String) async throws -> String {
        let response = try await http.execute(HttpRequest(method: .post, url: nonceEndpoint, headers: [("Accept", "application/json")]))
        try checkStatus(response, nonceEndpoint)
        guard case let .str(nonce)? = try parseObj(response, "nonce response")["c_nonce"] else {
            throw VciError.protocolError("nonce endpoint returned no c_nonce")
        }
        return nonce
    }

    private func postFormWithDpop(
        _ url: String, form: String, dpop: DpopProver, accessToken: String?, nonce: String? = nil
    ) async throws -> HttpResponse {
        var headers: [(String, String)] = [
            ("Content-Type", "application/x-www-form-urlencoded"),
            ("Accept", "application/json"),
            ("DPoP", try await dpop.proof(method: "POST", url: url, accessToken: accessToken, nonce: nonce)),
        ]
        if let accessToken { headers.append(("Authorization", "DPoP \(accessToken)")) }
        let response = try await http.execute(HttpRequest(method: .post, url: url, headers: headers, body: [UInt8](form.utf8)))

        if nonce == nil, let serverNonce = dpopNonceChallenge(response) {
            return try await postFormWithDpop(url, form: form, dpop: dpop, accessToken: accessToken, nonce: serverNonce)
        }
        try checkOAuth(response, url)
        return response
    }

    private func postJsonWithDpop(
        _ url: String, json: String, dpop: DpopProver, accessToken: String, nonce: String? = nil
    ) async throws -> HttpResponse {
        let headers: [(String, String)] = [
            ("Content-Type", "application/json"),
            ("Accept", "application/json"),
            ("DPoP", try await dpop.proof(method: "POST", url: url, accessToken: accessToken, nonce: nonce)),
            ("Authorization", "DPoP \(accessToken)"),
        ]
        let response = try await http.execute(HttpRequest(method: .post, url: url, headers: headers, body: [UInt8](json.utf8)))

        if nonce == nil, let serverNonce = dpopNonceChallenge(response) {
            return try await postJsonWithDpop(url, json: json, dpop: dpop, accessToken: accessToken, nonce: serverNonce)
        }
        try checkOAuth(response, url)
        return response
    }

    private func getJson(_ url: String) async throws -> JsonValue {
        let response = try await rawGet(url)
        try checkStatus(response, url)
        return try parseObj(response, url)
    }

    private func rawGet(_ url: String) async throws -> HttpResponse {
        try await http.execute(HttpRequest(method: .get, url: url, headers: [("Accept", "application/json")]))
    }

    private func dpopNonceChallenge(_ response: HttpResponse) -> String? {
        guard response.status == 400 || response.status == 401 else { return nil }
        return header(response, "DPoP-Nonce")
    }

    private func checkStatus(_ response: HttpResponse, _ endpoint: String) throws {
        guard (200...299).contains(response.status) else {
            throw VciError.http(status: response.status, endpoint: endpoint, body: bodyText(response, 500))
        }
    }

    private func checkOAuth(_ response: HttpResponse, _ endpoint: String) throws {
        if (200...299).contains(response.status) { return }
        if let text = String(bytes: response.body, encoding: .utf8),
           let obj = try? JsonValue.parse(text), case let .str(error)? = obj["error"] {
            var desc: String?
            if case let .str(d)? = obj["error_description"] { desc = d }
            throw VciError.oauth(error: error, description: desc, endpoint: endpoint)
        }
        throw VciError.http(status: response.status, endpoint: endpoint, body: bodyText(response, 500))
    }

    private func parseObj(_ response: HttpResponse, _ where_: String) throws -> JsonValue {
        guard let text = String(bytes: response.body, encoding: .utf8),
              let obj = try? JsonValue.parse(text), case .obj = obj
        else { throw VciError.protocolError("\(where_): not a JSON object") }
        return obj
    }

    private func header(_ response: HttpResponse, _ name: String) -> String? {
        response.headers.first { $0.0.caseInsensitiveCompare(name) == .orderedSame }?.1
    }

    private func bodyText(_ response: HttpResponse, _ limit: Int) -> String? {
        guard let text = String(bytes: response.body, encoding: .utf8) else { return nil }
        return String(text.prefix(limit))
    }

    private func wellKnown(_ base: String, _ suffix: String) throws -> String {
        var trimmed = base
        while trimmed.hasSuffix("/") { trimmed.removeLast() }
        guard trimmed.hasPrefix("https://") else { throw VciError.metadata("issuer must be https: \(base)") }
        let rest = String(trimmed.dropFirst("https://".count))
        if let slash = rest.firstIndex(of: "/") {
            let host = rest[rest.startIndex..<slash]
            let path = rest[slash...]
            return "https://\(host)/.well-known/\(suffix)\(path)"
        }
        return "https://\(rest)/.well-known/\(suffix)"
    }

    private func enc(_ v: String) -> String {
        var allowed = CharacterSet.alphanumerics
        allowed.insert(charactersIn: "-._~")
        return v.addingPercentEncoding(withAllowedCharacters: allowed) ?? v
    }
}
