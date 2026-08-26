import Foundation
import SdJwt
import WalletAPI

/// A localized string (BCP-47 `lang` + `value`) from a WRPRC `purpose` / `srv_description`.
public struct RegistrationLocalizedText: Equatable {
    public let lang: String
    public let value: String
    public init(lang: String, value: String) {
        self.lang = lang
        self.value = value
    }
}

/// The relying party's registration, as asserted by a registrar-issued WRPRC (ETSI TS 119 475) carried in
/// the request's `verifier_info` `registration_cert` element (ETSI TS 119 472-2 §6.3). Populated only when
/// the wallet is configured with registrar anchors and the request carries a WRPRC that validates + binds to
/// the WRPAC. The wallet layer additionally runs the Token Status List check over `status`.
public struct RegistrationInfo {
    /// `sub` — the registered semantic identifier, bound to the WRPAC organizationIdentifier (GEN-5.1.1-02).
    public let subject: String
    /// `name` — the relying party's display name (the **final** RP for an intermediated request), if present.
    public let subjectName: String?
    /// EU-level entitlements/roles asserted for the relying party (≥1).
    public let entitlements: [String]
    /// The declared intended-use, localized, for the consent screen.
    public let purpose: [RegistrationLocalizedText]
    /// When the RP operates through an intermediary: its identifier (`intermediary.sub`) and name (`sname`).
    public let intermediarySub: String?
    public let intermediaryName: String?
    /// The raw WRPRC `status` claim (`{ status_list: { idx, uri } }`), for the wallet-layer status check.
    public let status: JsonValue?
    /// True iff a registrar-issued WRPRC validated + bound to the WRPAC (authoritative, registrar-sealed).
    /// False when only the self-declared `registrar_dataset` backs this registration (no WRPRC present).
    public let attested: Bool
    /// The self-declared `registrar_dataset` (REQ-RO-02), when the request carried one.
    public let dataset: RegistrarDataset?
    /// The credentials/claims the RP is registered to request — from the WRPRC when `attested`, else the
    /// self-declared dataset — used for the attribute-scope check (RPRC_21).
    public let registeredCredentials: [RegisteredCredential]

    public init(subject: String, subjectName: String? = nil, entitlements: [String], purpose: [RegistrationLocalizedText],
                intermediarySub: String?, intermediaryName: String?, status: JsonValue?,
                attested: Bool = false, dataset: RegistrarDataset? = nil,
                registeredCredentials: [RegisteredCredential] = []) {
        self.subject = subject
        self.subjectName = subjectName
        self.entitlements = entitlements
        self.purpose = purpose
        self.intermediarySub = intermediarySub
        self.intermediaryName = intermediaryName
        self.status = status
        self.attested = attested
        self.dataset = dataset
        self.registeredCredentials = registeredCredentials
    }
}

/// What the wallet shows on the consent screen about the verifier and its trust status.
public struct VerifierInfo {
    public let clientId: String
    public let clientIdScheme: String
    /// X.509 chain from the request signature, leaf-first DER (nil for unsigned requests).
    public let certificateChainDer: [[UInt8]]?
    public let commonName: String?
    /// True only when the trust verifier confirmed signature + scheme + chain to a trust anchor.
    public let trusted: Bool
    /// The RP's registrar-issued registration (WRPRC), when one accompanied the request and validated.
    public let registration: RegistrationInfo?

    public init(clientId: String, clientIdScheme: String, certificateChainDer: [[UInt8]]?, commonName: String?,
                trusted: Bool, registration: RegistrationInfo? = nil) {
        self.clientId = clientId
        self.clientIdScheme = clientIdScheme
        self.certificateChainDer = certificateChainDer
        self.commonName = commonName
        self.trusted = trusted
        self.registration = registration
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

/// The JOSE `typ` every OpenID4VP Request Object must carry (§5, RFC 9101).
public let requestObjectTyp = "oauth-authz-req+jwt"

// The Digital Credentials API exchange protocol identifiers this specification defines (Appendix A.1):
// `openid4vp-v<version>-<request-type>`. Multi-signed is named so the wallet can refuse it explicitly.
let dcApiUnsigned = "openid4vp-v1-unsigned"
let dcApiSigned = "openid4vp-v1-signed"
let dcApiMultiSigned = "openid4vp-v1-multisigned"

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
    private let rng: (any Rng)?

    /// `rng` enables the `wallet_nonce` replay mitigation (§5.10) on `request_uri_method=post`: sending it
    /// is OPTIONAL, but once sent the verifier's request object MUST echo it. Without an `rng` no nonce is
    /// sent and nothing is validated.
    public init(http: any HttpTransport, trust: (any RequestTrustVerifier)? = nil, rng: (any Rng)? = nil) {
        self.http = http
        self.trust = trust
        self.rng = rng
    }

    public func resolve(_ requestUri: String) async throws -> ResolvedRequest {
        let params = try parseQuery(requestUri)
        guard let clientId = params["client_id"] else { throw VpError.invalidRequest("missing client_id") }
        let scheme = clientIdScheme(clientId)

        let claims: JsonValue
        let verifier: VerifierInfo
        // §8.5 `invalid_request_uri_method`: the value is case-sensitive and must be exactly get or post.
        let uriMethod = params["request_uri_method"] ?? "get"
        guard uriMethod == "get" || uriMethod == "post" else {
            throw VpError.invalidRequest("invalid_request_uri_method: '\(uriMethod)' is neither get nor post")
        }
        if params["request_uri"] != nil || params["request"] != nil { try requireSignableClientIdPrefix(scheme) }
        if let requestUriParam = params["request_uri"] {
            let walletNonce = uriMethod == "post" ? rng.map { Base64Url.encode($0.nextBytes(16)) } : nil
            let jwt = try await fetchRequestObject(requestUriParam, method: uriMethod, walletNonce: walletNonce)
            (claims, verifier) = try await parseSignedRequest(jwt, clientId, scheme, walletNonce: walletNonce)
        } else if let requestParam = params["request"] {
            (claims, verifier) = try await parseSignedRequest(requestParam, clientId, scheme, walletNonce: nil)
        } else {
            claims = try unsignedRequest(params)
            verifier = VerifierInfo(clientId: clientId, clientIdScheme: scheme, certificateChainDer: nil, commonName: nil, trusted: false)
        }

        return try build(claims, clientId, scheme, verifier)
    }

    /// Resolves an OpenID4VP request delivered over the W3C Digital Credentials API. The request
    /// object (unsigned JSON or a signed JWS) has no `response_uri`; `origin` is supplied by the
    /// platform and binds the presentation. Uses `dc_api` / `dc_api.jwt` response modes.
    ///
    /// `protocolId` is the exchange protocol identifier the platform delivered the request under
    /// (Appendix A.1, e.g. `openid4vp-v1-signed`). Pass it whenever the platform names one: it is checked
    /// against the shape of `requestObject`, so a request announced as signed cannot be processed as an
    /// unsigned one. Callers with no identifier to hand pass nil and the shape decides alone.
    public func resolveDcApi(_ requestObject: String, origin: String, protocolId: String? = nil) async throws -> ResolvedRequest {
        // OpenID4VP DC API / 18013-7 C.5: the platform Origin binds the presentation (and, unsigned, is the
        // verifier's identity). A blank origin binds nothing and must be rejected before it is used.
        guard !origin.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else { throw VpError.invalidRequest("DC API origin must not be blank") }
        let trimmed = requestObject.trimmingCharacters(in: .whitespacesAndNewlines)
        var envelope: JsonValue?
        if trimmed.hasPrefix("{") {
            let parsed = try JsonValue.parse(trimmed)
            guard case .obj = parsed else { throw VpError.invalidRequest("DC API request must be JSON") }
            envelope = parsed
        }
        try rejectMultiSigned(protocolId, envelope)
        // OpenID4VP 1.0 signed DC API: data is {"request": "<JWS>"} (JAR); the claims live in the JWS. A bare
        // JWS with no JSON envelope is accepted too — verifiers send the request object both ways.
        var signedRequest: String?
        if let envelope {
            if case let .str(request)? = envelope["request"] { signedRequest = request }
        } else {
            signedRequest = trimmed
        }
        try requireProtocolMatchesShape(protocolId, signed: signedRequest != nil)
        let claims: JsonValue
        let verifier: VerifierInfo
        if let signedRequest {
            (claims, verifier) = try await verifySignedDcApi(signedRequest, origin)
        } else {
            claims = envelope!
            // Unsigned (Appendix A.3.1): the Origin *is* the verifier's identity. The wallet MUST ignore
            // any `client_id` and any `expected_origins` such a request carries.
            verifier = VerifierInfo(clientId: origin, clientIdScheme: "origin", certificateChainDer: nil, commonName: nil, trusted: false)
        }
        return try build(claims, verifier.clientId, verifier.clientIdScheme, verifier, origin: origin)
    }

    /// Appendix A.3.2.2 multi-signed requests (JWS JSON Serialization) carry the request parameters in a
    /// base64url `payload` signed once per Client Identifier, so one request can authenticate under several
    /// trust frameworks. The SDK does not implement them; they are recognised — by protocol identifier and by
    /// the `{payload, signatures}` shape — so the wallet refuses them by name. Parsing one as an unsigned
    /// request would otherwise fail much later with a misleading "missing nonce".
    private func rejectMultiSigned(_ protocolId: String?, _ envelope: JsonValue?) throws {
        let multiSigned = protocolId == dcApiMultiSigned
            || isJwsJsonSerialization(envelope) || isJwsJsonSerialization(envelope?["request"])
        if multiSigned {
            throw VpError.unsupported("multi-signed DC API requests (\(dcApiMultiSigned)) are not supported")
        }
    }

    private func isJwsJsonSerialization(_ value: JsonValue?) -> Bool {
        guard let value, case .obj = value else { return false }
        guard case .str(_)? = value["payload"], case .arr(_)? = value["signatures"] else { return false }
        return true
    }

    /// The exchange protocol identifier names the request type (Appendix A.1) and the `data` shape must agree
    /// with it: `openid4vp-v1-signed` carries a JWS, `openid4vp-v1-unsigned` carries the request parameters
    /// themselves. Without this check, a request announced as signed whose data holds no JWS would resolve as
    /// an unsigned request — silently dropping both the signature and the `expected_origins` replay check,
    /// and presenting the caller Origin as the verifier. Identifiers this specification does not define leave
    /// the shape as the only signal.
    private func requireProtocolMatchesShape(_ protocolId: String?, signed: Bool) throws {
        let expectSigned: Bool
        switch protocolId {
        case dcApiSigned: expectSigned = true
        case dcApiUnsigned: expectSigned = false
        default: return
        }
        if expectSigned != signed {
            let actual = signed ? "a signed request (JWS)" : "an unsigned request"
            throw VpError.invalidRequest("DC API protocol '\(protocolId ?? "")' does not match the request: data is \(actual)")
        }
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

        // §5.9.3: under the `redirect_uri` prefix the Client Identifier *is* the endpoint the response goes to.
        var responseUri = str("response_uri")
        var redirectUri = str("redirect_uri")
        if scheme == redirectUriPrefix {
            let target = try redirectUriPrefixTarget(claims, clientId, responseMode)
            if usesResponseUri(responseMode) { responseUri = target } else { redirectUri = target }
        }

        return ResolvedRequest(
            clientId: clientId, nonce: nonce, state: str("state"),
            responseMode: responseMode, responseUri: responseUri, redirectUri: redirectUri,
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

    /// Signed DC API request: the client_id (and thus its prefix/scheme) come from the JWS claims, not query params.
    private func verifySignedDcApi(_ jwt: String, _ origin: String) async throws -> (JsonValue, VerifierInfo) {
        let jws = try Jws.parse(jwt)
        try requireRequestObjectTyp(jws)
        guard let text = String(bytes: jws.payloadBytes, encoding: .utf8),
              let claims = try? JsonValue.parse(text), case .obj = claims
        else { throw VpError.invalidRequest("signed DC API request payload must be JSON") }
        try checkExpectedOrigins(claims, origin)
        // Appendix A.2: client_id MUST be present in a signed request — it selects the Client Identifier Prefix.
        guard case let .str(clientId)? = claims["client_id"] else {
            throw VpError.invalidRequest("signed DC API request has no client_id")
        }
        // OpenID4VP 1.0: the scheme is the client_id prefix (no separate client_id_scheme parameter).
        let scheme = clientIdScheme(clientId)
        try requireSignableClientIdPrefix(scheme) // §5.9.3 — this request is signed by construction
        let verifier: VerifierInfo
        if let trust {
            verifier = try await trust.verifyRequestObject(jws, clientId: clientId, scheme: scheme)
        } else {
            verifier = VerifierInfo(clientId: clientId, clientIdScheme: scheme, certificateChainDer: jws.x5c, commonName: nil, trusted: false)
        }
        return (claims, verifier)
    }

    /// OpenID4VP Appendix A.2 — `expected_origins` is REQUIRED in signed DC API requests: the wallet MUST
    /// compare it against the platform-supplied Origin "to detect replay of the request from a malicious
    /// Verifier", and MUST error when no entry matches. A signature proves *who authored* a request, not
    /// *where it may be used*; the signed list and the platform Origin come from two channels the calling
    /// page controls neither of. Absent or empty is rejected — the guarantee cannot be evaluated.
    private func checkExpectedOrigins(_ claims: JsonValue, _ origin: String) throws {
        guard case let .arr(entries)? = claims["expected_origins"] else {
            throw VpError.invalidRequest("signed DC API request has no expected_origins")
        }
        if entries.isEmpty { throw VpError.invalidRequest("expected_origins must be a non-empty array") }
        let origins: [String] = try entries.map {
            guard case let .str(value) = $0 else { throw VpError.invalidRequest("expected_origins entries must be strings") }
            return value
        }
        guard origins.contains(origin) else {
            throw VpError.invalidRequest("origin '\(origin)' does not match expected_origins \(origins)")
        }
    }

    private func parseSignedRequest(
        _ jwt: String, _ clientId: String, _ scheme: String, walletNonce: String?
    ) async throws -> (JsonValue, VerifierInfo) {
        let jws = try Jws.parse(jwt)
        try requireRequestObjectTyp(jws)
        guard let text = String(bytes: jws.payloadBytes, encoding: .utf8),
              let claims = try? JsonValue.parse(text), case .obj = claims
        else { throw VpError.invalidRequest("request object payload must be JSON") }
        // §5.10.1: the Request Object's client_id MUST equal the Authorization Request's, prefix included.
        // (An `iss` claim, if present, is ignored — §5.)
        guard case let .str(objectClientId)? = claims["client_id"] else {
            throw VpError.invalidRequest("request object has no client_id")
        }
        guard objectClientId == clientId else {
            throw VpError.invalidRequest("request object client_id '\(objectClientId)' != request client_id '\(clientId)'")
        }
        // §5.10: having sent a wallet_nonce, the wallet MUST terminate unless the request object echoes it.
        if let walletNonce {
            guard case let .str(echoed)? = claims["wallet_nonce"], echoed == walletNonce else {
                throw VpError.invalidRequest("request object does not echo the wallet_nonce")
            }
        }
        let verifier: VerifierInfo
        if let trust {
            verifier = try await trust.verifyRequestObject(jws, clientId: clientId, scheme: scheme)
        } else {
            verifier = VerifierInfo(clientId: clientId, clientIdScheme: scheme, certificateChainDer: jws.x5c, commonName: nil, trusted: false)
        }
        return (claims, verifier)
    }

    /// §5: "Wallets MUST NOT process Request Objects where the `typ` Header Parameter is not present or
    /// does not have the value `oauth-authz-req+jwt`." Typing the JWS stops a token minted for another
    /// purpose (an ID token, a key-proof JWT) from being replayed as an authorization request.
    private func requireRequestObjectTyp(_ jws: Jws) throws {
        guard case let .str(typ)? = jws.header["typ"], typ == requestObjectTyp else {
            throw VpError.invalidRequest("request object typ must be '\(requestObjectTyp)'")
        }
    }

    /// Fetches the request object from `request_uri`. With `request_uri_method=post` (OpenID4VP §5.10)
    /// the wallet POSTs its capabilities as `wallet_metadata` — and, when available, a fresh
    /// `walletNonce` the verifier must echo in the signed request object; otherwise it GETs the URL.
    private func fetchRequestObject(_ url: String, method: String, walletNonce: String?) async throws -> String {
        let request: HttpRequest
        if method == "post" {
            var form = "wallet_metadata=\(formEncode(walletMetadataJson))"
            if let walletNonce { form += "&wallet_nonce=\(formEncode(walletNonce))" }
            request = HttpRequest(method: .post, url: url, headers: [
                ("Accept", "application/oauth-authz-req+jwt"),
                ("Content-Type", "application/x-www-form-urlencoded"),
            ], body: Array(form.utf8))
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

    /// OpenID4VP 1.0 §5.9.2: the Client Identifier Prefix is the part before the first `:` — but only when that
    /// part is a prefix §5.9.3 defines. "If a `:` character is not present in the Client Identifier, the Wallet
    /// MUST treat the Client Identifier as referencing a pre-registered client", and pre-registered identifiers
    /// "MUST NOT contain a `:` character preceded immediately by a supported Client Identifier Prefix value" —
    /// so an unrecognised head is not a prefix at all. Without the whitelist a bare Redirect URI client_id
    /// (`https://rp.example/cb`) would parse as the non-existent prefix `https`.
    private func clientIdScheme(_ clientId: String) -> String {
        guard let head = clientId.split(separator: ":", maxSplits: 1, omittingEmptySubsequences: false).first,
              clientIdPrefixes.contains(String(head))
        else { return preRegisteredPrefix }
        return String(head)
    }

    /// §5.9.3: "Requests using the `redirect_uri` Client Identifier Prefix cannot be signed because there is no
    /// method for the Wallet to obtain a trusted key for verification." A JWS under this prefix carries no
    /// verifiable key, so accepting one would let an attacker dress an unauthenticated request as a signed
    /// (and, to the User, "verified") one. The prefix and JAR are mutually exclusive — reject before fetching.
    private func requireSignableClientIdPrefix(_ scheme: String) throws {
        if scheme == redirectUriPrefix {
            throw VpError.invalidRequest("the '\(redirectUriPrefix)' client_id prefix cannot be used with a signed request")
        }
    }

    /// §5.9.3: `direct_post` (and its `.jwt` variant) posts to `response_uri`; every other mode uses `redirect_uri`.
    private func usesResponseUri(_ responseMode: String) -> Bool { responseMode.hasPrefix("direct_post") }

    /// §5.9.3: under the `redirect_uri` prefix "the original Client Identifier part (without the prefix
    /// `redirect_uri:`) is the Verifier's Redirect URI (or Response URI when Response Mode `direct_post` is
    /// used)". Nothing else authenticates such a Verifier — the identifier *is* the endpoint — so a request
    /// naming one Verifier while delivering the presentation to another endpoint is rejected. The Verifier
    /// "MAY omit" the parameter, in which case the Client Identifier supplies it.
    private func redirectUriPrefixTarget(_ claims: JsonValue, _ clientId: String, _ responseMode: String) throws -> String {
        let prefix = "\(redirectUriPrefix):"
        let expected = clientId.hasPrefix(prefix) ? String(clientId.dropFirst(prefix.count)) : clientId
        let param = usesResponseUri(responseMode) ? "response_uri" : "redirect_uri"
        guard case let .str(declared)? = claims[param] else { return expected }
        if declared != expected {
            throw VpError.invalidRequest("\(param) '\(declared)' does not match the client_id '\(clientId)'")
        }
        return declared
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

/// §5.9.2: an unprefixed (or unrecognised-prefix) Client Identifier references a pre-registered client.
private let preRegisteredPrefix = "pre-registered"

/// §5.9.3: the Client Identifier is the Verifier's Redirect URI (Response URI under `direct_post`).
private let redirectUriPrefix = "redirect_uri"

/// The Client Identifier Prefixes OpenID4VP 1.0 §5.9.3 defines. Everything else is `preRegisteredPrefix`.
private let clientIdPrefixes: Set<String> = [
    redirectUriPrefix,
    "openid_federation",
    "decentralized_identifier",
    "verifier_attestation",
    "x509_san_dns",
    "x509_hash",
]

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
