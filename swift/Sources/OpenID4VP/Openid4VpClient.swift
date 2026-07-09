import CborCose
import Foundation
import SdJwt
import WalletAPI

/// Per-query choice: which held credential to present for a DCQL credential-query id.
public struct PresentationSelection {
    public let chosen: [String: String]

    public init(chosen: [String: String]) {
        self.chosen = chosen
    }

    /// Auto-pick the first candidate for every required query.
    public static func auto(_ matches: DcqlMatchResult) -> PresentationSelection {
        var chosen: [String: String] = [:]
        for qid in matches.requiredQueryIds {
            if let first = matches.candidatesByQuery[qid]?.first {
                chosen[qid] = first.credential.credentialId
            }
        }
        return PresentationSelection(chosen: chosen)
    }
}

public struct SubmitResult {
    public let redirectUri: String?
}

/// OpenID4VP 1.0 client (wallet/holder side) over the `HttpTransport` port.
public struct Openid4VpClient {
    private let http: any HttpTransport
    private let clock: () -> Int64
    private let resolver: AuthorizationRequestResolver

    /// `rng` enables the `wallet_nonce` replay mitigation on `request_uri_method=post` (§5.10); nil = don't send one.
    public init(http: any HttpTransport, clock: @escaping () -> Int64, trust: (any RequestTrustVerifier)? = nil,
                rng: (any Rng)? = nil) {
        self.http = http
        self.clock = clock
        self.resolver = AuthorizationRequestResolver(http: http, trust: trust, rng: rng)
    }

    public func resolveRequest(_ requestUri: String) async throws -> ResolvedRequest {
        try await resolver.resolve(requestUri)
    }

    /// Resolves an OpenID4VP request delivered over the Digital Credentials API (with the caller `origin`).
    public func resolveDcApiRequest(_ requestObject: String, origin: String) async throws -> ResolvedRequest {
        try await resolver.resolveDcApi(requestObject, origin: origin)
    }

    public func match(_ request: ResolvedRequest, held: [any PresentableCredential]) -> DcqlMatchResult {
        DcqlEngine.match(request.dcqlQuery, held: held)
    }

    public func respond(
        request: ResolvedRequest,
        matches: DcqlMatchResult,
        selection: PresentationSelection,
        held: [any PresentableCredential]
    ) async throws -> SubmitResult {
        let vpToken = try await buildVpToken(request: request, matches: matches, selection: selection, held: held)
        switch request.responseMode {
        case "direct_post": return try await submitDirectPost(request, vpToken)
        case "direct_post.jwt": return try await submitDirectPostJwt(request, vpToken)
        default: throw VpError.unsupported("response_mode \(request.responseMode)")
        }
    }

    /// Builds the presentations for a Digital Credentials API request and returns the response object
    /// to hand back to the platform (no HTTP POST): `{vp_token}` for `dc_api`, `{response: <JWE>}` for
    /// `dc_api.jwt`. mdoc presentations bind the caller origin via the DC API handover.
    public func respondDcApi(
        request: ResolvedRequest,
        matches: DcqlMatchResult,
        selection: PresentationSelection,
        held: [any PresentableCredential]
    ) async throws -> JsonValue {
        let vpToken = try await buildVpToken(request: request, matches: matches, selection: selection, held: held)
        switch request.responseMode {
        case "dc_api":
            return .obj([("vp_token", vpToken)])
        case "dc_api.jwt":
            guard let recipient = verifierEncryptionKey(request) else {
                throw VpError.invalidRequest("dc_api.jwt but no verifier encryption key in client_metadata")
            }
            let jwe = try Jwe.encryptEcdhEs(plaintext: [UInt8](JsonValue.obj([("vp_token", vpToken)]).serialize().utf8), recipient: recipient, enc: encValue(request))
            return .obj([("response", .str(jwe))])
        default:
            throw VpError.unsupported("respondDcApi requires a dc_api response_mode, got \(request.responseMode)")
        }
    }

    /// Sends an Authorization Error Response (§8.5) to the verifier's `response_uri`: a form POST of
    /// `error` / `error_description` / `state`, symmetric to the success submission. Returns the
    /// verifier's `redirect_uri` when it supplies one — which the wallet MUST then follow.
    ///
    /// Only defined for the `direct_post` response modes. Over the Digital Credentials API there is no
    /// `response_uri`; the error is handed back to the platform, and §15.9.2 warns that returning
    /// protocol errors there can itself reveal whether the wallet holds a matching credential.
    public func reportError(
        _ request: ResolvedRequest,
        code: VpErrorCode,
        description: String? = nil
    ) async throws -> SubmitResult {
        guard let responseUri = request.responseUri else {
            throw VpError.unsupported("error responses are only sent to a response_uri (direct_post)")
        }
        var form = "error=\(enc(code.code))"
        if let description { form += "&error_description=\(enc(description))" }
        if let state = request.state { form += "&state=\(enc(state))" }
        return try await post(responseUri, form)
    }

    private func buildVpToken(
        request: ResolvedRequest,
        matches: DcqlMatchResult,
        selection: PresentationSelection,
        held: [any PresentableCredential]
    ) async throws -> JsonValue {
        let missing = matches.requiredQueryIds.filter { selection.chosen[$0] == nil }
        if !missing.isEmpty { throw VpError.queryNotSatisfiable(missing: Set(missing)) }

        var heldById: [String: any PresentableCredential] = [:]
        for h in held { heldById[h.credentialId] = h }
        let iat = clock()
        // Encrypted responses (direct_post.jwt / dc_api.jwt) bind the verifier's encryption key in the mdoc handover.
        let jwkThumbprint: [UInt8]? = request.responseMode.hasSuffix(".jwt")
            ? verifierEncryptionKey(request).map { ecJwkThumbprint($0) } : nil

        var vpEntries: [(String, JsonValue)] = []
        for (queryId, credentialId) in selection.chosen {
            guard let candidate = matches.candidatesByQuery[queryId]?.first(where: { $0.credential.credentialId == credentialId }) else {
                throw VpError.selectionIncomplete("no candidate \(credentialId) for query \(queryId)")
            }
            guard let cred = heldById[credentialId] else {
                throw VpError.selectionIncomplete("unknown credential \(credentialId)")
            }
            let presentation = try await cred.present(PresentationContext(
                disclosedPaths: candidate.disclosedPaths,
                clientId: request.clientId, nonce: request.nonce, responseUri: request.responseUri,
                issuedAt: iat, transactionData: request.transactionData, verifierJwkThumbprint: jwkThumbprint, origin: request.origin
            ))
            vpEntries.append((queryId, .arr([.str(presentation)])))
        }
        return .obj(vpEntries)
    }

    private func submitDirectPost(_ request: ResolvedRequest, _ vpToken: JsonValue) async throws -> SubmitResult {
        guard let responseUri = request.responseUri else { throw VpError.invalidRequest("direct_post needs response_uri") }
        var form = "vp_token=\(enc(vpToken.serialize()))"
        if let state = request.state { form += "&state=\(enc(state))" }
        return try await post(responseUri, form)
    }

    private func submitDirectPostJwt(_ request: ResolvedRequest, _ vpToken: JsonValue) async throws -> SubmitResult {
        guard let responseUri = request.responseUri else { throw VpError.invalidRequest("direct_post.jwt needs response_uri") }
        guard let recipient = verifierEncryptionKey(request) else {
            throw VpError.invalidRequest("direct_post.jwt but no verifier encryption key in client_metadata")
        }
        var entries: [(String, JsonValue)] = [("vp_token", vpToken)]
        if let state = request.state { entries.append(("state", .str(state))) }
        let jwe = try Jwe.encryptEcdhEs(plaintext: [UInt8](JsonValue.obj(entries).serialize().utf8), recipient: recipient, enc: encValue(request))
        return try await post(responseUri, "response=\(enc(jwe))")
    }

    private func post(_ url: String, _ form: String) async throws -> SubmitResult {
        let resp = try await http.execute(HttpRequest(
            method: .post, url: url,
            headers: [("Content-Type", "application/x-www-form-urlencoded"), ("Accept", "application/json")],
            body: [UInt8](form.utf8)
        ))
        guard (200...299).contains(resp.status) else {
            throw VpError.responseFailed("verifier returned HTTP \(resp.status)")
        }
        if let text = String(bytes: resp.body, encoding: .utf8), let body = try? JsonValue.parse(text),
           case let .str(redirect)? = body["redirect_uri"] {
            return SubmitResult(redirectUri: redirect)
        }
        return SubmitResult(redirectUri: nil)
    }

    private func verifierEncryptionKey(_ request: ResolvedRequest) -> EcPublicKey? {
        guard let jwks = request.clientMetadata?["jwks"], case let .arr(keys)? = jwks["keys"] else { return nil }
        let encKey = keys.first { if case .str("enc")? = $0["use"] { return true } else { return false } } ?? keys.first
        return encKey.flatMap { JwkEc.fromJson($0) }
    }

    private func encValue(_ request: ResolvedRequest) -> JweEnc {
        if case let .arr(items)? = request.clientMetadata?["encrypted_response_enc_values_supported"],
           case let .str(id)? = items.first {
            return JweEnc.from(id) ?? .a128gcm
        }
        if case let .str(id)? = request.clientMetadata?["authorization_encrypted_response_enc"] {
            return JweEnc.from(id) ?? .a128gcm
        }
        return .a128gcm
    }

    private func enc(_ v: String) -> String {
        var allowed = CharacterSet.alphanumerics
        allowed.insert(charactersIn: "-._~")
        return v.addingPercentEncoding(withAllowedCharacters: allowed) ?? v
    }
}
