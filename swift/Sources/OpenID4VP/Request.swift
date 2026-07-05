import Foundation
import SdJwt
import WalletAPI

/// What the wallet shows on the consent screen about the verifier and its trust status.
public struct VerifierInfo {
    public let clientId: String
    public let clientIdScheme: String
    /// X.509 chain from the request signature, leaf-first DER (nil for unsigned requests).
    public let certificateChainDer: [[UInt8]]?
    public let commonName: String?
    /// True only when the trust verifier confirmed signature + scheme + chain to a trust anchor.
    public let trusted: Bool

    public init(clientId: String, clientIdScheme: String, certificateChainDer: [[UInt8]]?, commonName: String?, trusted: Bool) {
        self.clientId = clientId
        self.clientIdScheme = clientIdScheme
        self.certificateChainDer = certificateChainDer
        self.commonName = commonName
        self.trusted = trusted
    }
}

/// Verifies an OpenID4VP signed request object: JWS signature, client_id scheme
/// (x509_san_dns / x509_hash), and the certificate chain to a trust anchor. Implemented by
/// the `Trust` module (swift-certificates); the resolver stays platform-neutral.
public protocol RequestTrustVerifier: Sendable {
    func verifyRequestObject(_ jws: Jws, clientId: String, scheme: String) async throws -> VerifierInfo
}

public struct ResolvedRequest {
    public let clientId: String
    public let nonce: String
    public let state: String?
    public let responseMode: String
    public let responseUri: String?
    public let redirectUri: String?
    public let dcqlQuery: DcqlQuery
    public let clientMetadata: JsonValue?
    public let transactionData: [String]?
    public let verifier: VerifierInfo
    /// Caller web origin for a Digital Credentials API request (nil for the URL/QR flow).
    public let origin: String?

    public init(clientId: String, nonce: String, state: String?, responseMode: String, responseUri: String?,
                redirectUri: String?, dcqlQuery: DcqlQuery, clientMetadata: JsonValue?, transactionData: [String]?,
                verifier: VerifierInfo, origin: String? = nil) {
        self.clientId = clientId; self.nonce = nonce; self.state = state; self.responseMode = responseMode
        self.responseUri = responseUri; self.redirectUri = redirectUri; self.dcqlQuery = dcqlQuery
        self.clientMetadata = clientMetadata; self.transactionData = transactionData; self.verifier = verifier; self.origin = origin
    }
}

/// Resolves an OpenID4VP authorization request (OpenID4VP §5): parses the request URI and
/// follows JAR (`request_uri`/`request`).
///
/// NOTE: `x509_san_dns` signature/SAN verification needs X.509 parsing (swift-certificates),
/// which lands with the trust module (M3, mirrors the issuer-x5c gap). This resolver handles
/// unsigned requests and parses signed request objects; on Apple/Linux without the trust
/// module it reports `signatureValid = false` for x509 schemes rather than asserting trust.
public struct AuthorizationRequestResolver {
    private let http: any HttpTransport
    private let trust: (any RequestTrustVerifier)?

    public init(http: any HttpTransport, trust: (any RequestTrustVerifier)? = nil) {
        self.http = http
        self.trust = trust
    }

    public func resolve(_ requestUri: String) async throws -> ResolvedRequest {
        let params = try parseQuery(requestUri)
        guard let clientId = params["client_id"] else { throw VpError.invalidRequest("missing client_id") }
        let scheme = clientIdScheme(clientId, params["client_id_scheme"])

        let claims: JsonValue
        let verifier: VerifierInfo
        let uriMethod = (params["request_uri_method"] ?? "get").lowercased()
        if let requestUriParam = params["request_uri"] {
            let jwt = try await fetchRequestObject(requestUriParam, method: uriMethod)
            (claims, verifier) = try await parseSignedRequest(jwt, clientId, scheme)
        } else if let requestParam = params["request"] {
            (claims, verifier) = try await parseSignedRequest(requestParam, clientId, scheme)
        } else {
            claims = try unsignedRequest(params)
            verifier = VerifierInfo(clientId: clientId, clientIdScheme: scheme, certificateChainDer: nil, commonName: nil, trusted: false)
        }

        return try build(claims, clientId, scheme, verifier)
    }

    /// Resolves an OpenID4VP request delivered over the W3C Digital Credentials API. The request
    /// object (unsigned JSON or a signed JWS) has no `response_uri`; `origin` is supplied by the
    /// platform and binds the presentation. Uses `dc_api` / `dc_api.jwt` response modes.
    public func resolveDcApi(_ requestObject: String, origin: String) async throws -> ResolvedRequest {
        let trimmed = requestObject.trimmingCharacters(in: .whitespacesAndNewlines)
        let claims: JsonValue
        let verifier: VerifierInfo
        if trimmed.hasPrefix("{") {
            let envelope = try JsonValue.parse(trimmed)
            if case let .str(signedRequest)? = envelope["request"] {
                // OpenID4VP 1.0 signed DC API: data is {"request": "<JWS>"} (JAR); the claims live in the JWS.
                let (c, v) = try await parseSignedRequest(signedRequest, origin, "x509_san_dns")
                claims = c
                var clientId = origin
                if case let .str(cid)? = c["client_id"] { clientId = cid }
                verifier = VerifierInfo(clientId: clientId, clientIdScheme: v.clientIdScheme, certificateChainDer: v.certificateChainDer, commonName: v.commonName, trusted: v.trusted)
            } else {
                claims = envelope
                var clientId = origin
                if case let .str(c)? = envelope["client_id"] { clientId = c }
                verifier = VerifierInfo(clientId: clientId, clientIdScheme: "web-origin", certificateChainDer: nil, commonName: nil, trusted: false)
            }
        } else {
            let (c, v) = try await parseSignedRequest(trimmed, origin, "x509_san_dns")
            claims = c
            var clientId = origin
            if case let .str(cid)? = c["client_id"] { clientId = cid }
            verifier = VerifierInfo(clientId: clientId, clientIdScheme: v.clientIdScheme, certificateChainDer: v.certificateChainDer, commonName: v.commonName, trusted: v.trusted)
        }
        return try build(claims, verifier.clientId, verifier.clientIdScheme, verifier, origin: origin)
    }

    private func build(_ claims: JsonValue, _ clientId: String, _ scheme: String, _ verifier: VerifierInfo, origin: String? = nil) throws -> ResolvedRequest {
        guard case let .str(nonce)? = claims["nonce"] else { throw VpError.invalidRequest("missing nonce") }
        guard let dcqlObj = claims["dcql_query"], case .obj = dcqlObj else {
            throw VpError.invalidRequest("missing dcql_query (only DCQL is supported)")
        }
        var responseMode = origin != nil ? "dc_api" : "direct_post"
        if case let .str(m)? = claims["response_mode"] { responseMode = m }
        guard ["direct_post", "direct_post.jwt", "dc_api", "dc_api.jwt"].contains(responseMode) else {
            throw VpError.unsupported("response_mode '\(responseMode)'")
        }
        var txData: [String]?
        if case let .arr(items)? = claims["transaction_data"] {
            txData = items.compactMap { if case let .str(s) = $0 { return s } else { return nil } }
        }
        func str(_ n: String) -> String? { if case let .str(s)? = claims[n] { return s }; return nil }
        return ResolvedRequest(
            clientId: clientId, nonce: nonce, state: str("state"),
            responseMode: responseMode, responseUri: str("response_uri"), redirectUri: str("redirect_uri"),
            dcqlQuery: try DcqlQuery.parse(dcqlObj), clientMetadata: claims["client_metadata"],
            transactionData: txData, verifier: verifier, origin: origin
        )
    }

    private func unsignedRequest(_ params: [String: String]) throws -> JsonValue {
        var entries: [(String, JsonValue)] = []
        for (k, v) in params {
            if k == "dcql_query" || k == "client_metadata" || k == "transaction_data" {
                entries.append((k, try JsonValue.parse(v)))
            } else {
                entries.append((k, .str(v)))
            }
        }
        return .obj(entries)
    }

    private func parseSignedRequest(_ jwt: String, _ clientId: String, _ scheme: String) async throws -> (JsonValue, VerifierInfo) {
        let jws = try Jws.parse(jwt)
        guard let text = String(bytes: jws.payloadBytes, encoding: .utf8),
              let claims = try? JsonValue.parse(text), case .obj = claims
        else { throw VpError.invalidRequest("request object payload must be JSON") }
        let verifier: VerifierInfo
        if let trust {
            verifier = try await trust.verifyRequestObject(jws, clientId: clientId, scheme: scheme)
        } else {
            verifier = VerifierInfo(clientId: clientId, clientIdScheme: scheme, certificateChainDer: jws.x5c, commonName: nil, trusted: false)
        }
        return (claims, verifier)
    }

    /// Fetches the request object from `request_uri`. With `request_uri_method=post` (OpenID4VP §5.10)
    /// the wallet POSTs its capabilities as `wallet_metadata` so the verifier can tailor the request;
    /// otherwise it GETs the URL.
    private func fetchRequestObject(_ url: String, method: String) async throws -> String {
        let request: HttpRequest
        if method == "post" {
            let body = Array("wallet_metadata=\(formEncode(walletMetadataJson))".utf8)
            request = HttpRequest(method: .post, url: url, headers: [
                ("Accept", "application/oauth-authz-req+jwt"),
                ("Content-Type", "application/x-www-form-urlencoded"),
            ], body: body)
        } else {
            request = HttpRequest(method: .get, url: url, headers: [("Accept", "application/oauth-authz-req+jwt")])
        }
        let resp = try await http.execute(request)
        guard (200...299).contains(resp.status) else { throw VpError.invalidRequest("request_uri fetch failed: HTTP \(resp.status)") }
        return (String(bytes: resp.body, encoding: .utf8) ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
    }

    private func formEncode(_ s: String) -> String {
        var allowed = CharacterSet.alphanumerics
        allowed.insert(charactersIn: "-_.*")
        return s.addingPercentEncoding(withAllowedCharacters: allowed) ?? s
    }

    private func clientIdScheme(_ clientId: String, _ explicit: String?) -> String {
        if let explicit { return explicit }
        if clientId.contains(":") { return String(clientId.split(separator: ":")[0]) }
        return "redirect_uri"
    }

    private func parseQuery(_ uri: String) throws -> [String: String] {
        guard let q = uri.split(separator: "?", maxSplits: 1).dropFirst().first else {
            throw VpError.invalidRequest("no query parameters in request")
        }
        var out: [String: String] = [:]
        for pair in q.split(separator: "&") {
            let kv = pair.split(separator: "=", maxSplits: 1)
            let k = String(kv[0]).removingPercentEncoding ?? String(kv[0])
            let v = kv.count > 1 ? (String(kv[1]).removingPercentEncoding ?? String(kv[1])) : ""
            out[k] = v
        }
        return out
    }
}

/// Wallet capabilities advertised to the verifier for `request_uri_method=post`.
private let walletMetadataJson: String = JsonValue.obj([
    ("vp_formats_supported", JsonValue.obj([
        ("dc+sd-jwt", JsonValue.obj([
            ("sd-jwt_alg_values", JsonValue.arr([.str("ES256")])),
            ("kb-jwt_alg_values", JsonValue.arr([.str("ES256")])),
        ])),
        ("mso_mdoc", JsonValue.obj([("alg_values", JsonValue.arr([.str("ES256")]))])),
    ])),
    // OpenID4VP 1.0 final: client_id_prefixes_supported (renamed from client_id_schemes_supported).
    ("client_id_prefixes_supported", JsonValue.arr([.str("x509_san_dns"), .str("x509_hash"), .str("redirect_uri")])),
    ("request_object_signing_alg_values_supported", JsonValue.arr([.str("ES256")])),
    ("response_types_supported", JsonValue.arr([.str("vp_token")])),
    ("response_modes_supported", JsonValue.arr([.str("direct_post"), .str("direct_post.jwt")])),
]).serialize()
