import CborCose
import Crypto
import Foundation
import SdJwt
import WalletAPI
@testable import OpenID4VCI

/// A mock OpenID4VCI issuer that actually verifies DPoP + key proofs and issues a real
/// SD-JWT VC. Not a stub: signatures, htu/htm/ath, aud and c_nonce are checked, and the
/// first token request is answered with a DPoP-Nonce challenge to exercise the retry path.
public actor MockIssuer: HttpTransport {
    private let area: SoftwareSecureArea
    private let issuerKey: KeyInfo
    private let now: Int64

    private let issuer = "https://issuer.example"
    private let preAuthCode = "PRE-AUTH-123"
    private var cNonce: String?
    private var accessToken: String?
    public private(set) var seenDpopNonceRetry = false

    // authorization code flow state
    private var parRequestUri: String?
    private let authCode = "AUTH-CODE-XYZ"
    private var authCodeChallenge: String?
    public private(set) var seenPar = false
    /// Test-observable: the key_attestation header from the first proof, and the proof count.
    public private(set) var seenKeyAttestation: String?
    public private(set) var seenProofCount = 0

    /// When set, the token response binds these `credential_identifiers` to the config (§8.2), so the wallet
    /// must request with a `credential_identifier`.
    private var credentialIdentifiers: [String]?
    public func setCredentialIdentifiers(_ ids: [String]?) { credentialIdentifiers = ids }
    /// The `credential_identifier` / `credential_configuration_id` the last Credential Request carried.
    public private(set) var seenCredentialIdentifier: String?
    public private(set) var seenConfigurationId: String?

    /// When true, the config advertises the `attestation` proof type (§8.2.1 Appendix F.3) in its metadata.
    private var supportsAttestationProof = false
    public func setSupportsAttestationProof(_ enabled: Bool) { supportsAttestationProof = enabled }
    private var requiresKeyAttestation = false
    public func setRequiresKeyAttestation(_ enabled: Bool) { requiresKeyAttestation = enabled }
    /// The `attestation`-proof Key Attestation JWT the last Credential Request carried (§8.2.1.3), if any.
    public private(set) var seenAttestationProof: String?

    /* ---- OpenID4VCI §8.2/§10 encrypted Credential Requests & Responses ---- */

    /// When set, the metadata advertises request/response encryption. `required` forces the wallet to use it.
    public var encryptionSupported = false
    public var encryptionRequired = false
    public func setEncryption(supported: Bool, required: Bool = false) {
        encryptionSupported = supported
        encryptionRequired = required
    }

    public private(set) var seenEncryptedRequest = false
    public private(set) var seenRequestKid: String?
    public private(set) var seenResponseEnc: String?

    public let requestEncKid = "mock-request-enc-key"
    private let requestEncKey = JweRecipientKey()

    private func requestEncryptionJson() -> String {
        var entries: [(String, JsonValue)] = []
        if case let .obj(e) = JwkEc.toJson(requestEncKey.publicKey) { entries = e }
        entries += [("use", .str("enc")), ("alg", .str("ECDH-ES")), ("kid", .str(requestEncKid))]
        let jwk = JsonValue.obj(entries).serialize()
        return #""credential_request_encryption":{"jwks":{"keys":[\#(jwk)]},"enc_values_supported":["A256GCM","A128GCM"],"encryption_required":\#(encryptionRequired)},"#
    }

    private func responseEncryptionJson() -> String {
        #""credential_response_encryption":{"alg_values_supported":["ECDH-ES"],"enc_values_supported":["A256GCM","A128GCM"],"encryption_required":\#(encryptionRequired)},"#
    }

    /// When true, /credential defers (returns a transaction_id); the credential comes from /deferred_credential.
    private var deferMode = false
    private var deferredHolderKey: EcPublicKey?
    private var deferredPollCount = 0
    /// Test-observable: (notification_id, event) of the last notification received.
    public private(set) var seenNotification: (String, String)?

    public func setDeferMode(_ enabled: Bool) { deferMode = enabled }

    public init(area: SoftwareSecureArea, issuerKey: KeyInfo, now: Int64) {
        self.area = area
        self.issuerKey = issuerKey
        self.now = now
    }

    public nonisolated var credentialOfferJson: String {
        """
        {"credential_issuer":"https://issuer.example",
         "credential_configuration_ids":["eu.europa.ec.eudi.pid.1"],
         "grants":{"urn:ietf:params:oauth:grant-type:pre-authorized_code":
           {"pre-authorized_code":"PRE-AUTH-123","tx_code":{"length":4,"input_mode":"numeric"}}}}
        """
    }

    public func execute(_ request: HttpRequest) async throws -> HttpResponse {
        let path = String(request.url.dropFirst(issuer.count))
        switch path {
        case "/.well-known/openid-credential-issuer": return handleIssuerMetadata(request)
        case "/.well-known/oauth-authorization-server": return ok(asMetadata())
        case "/.well-known/jwt-vc-issuer": return ok(jwtVcIssuerMetadata())
        case "/token": return try await handleToken(request)
        case "/nonce": return handleNonce()
        case "/credential": return try await handleCredential(request)
        case "/deferred_credential": return try await handleDeferred(request)
        case "/notification": return try handleNotification(request)
        case "/par": return handlePar(request)
        default:
            if path.hasPrefix("/authorize") { return handleAuthorize(request) }
            return HttpResponse(status: 404, headers: [], body: [UInt8]("not found".utf8))
        }
    }

    private func handlePar(_ request: HttpRequest) -> HttpResponse {
        seenPar = true
        let form = parseForm(String(bytes: request.body ?? [], encoding: .utf8) ?? "")
        precondition(form["response_type"] == "code", "PAR: response_type must be code")
        precondition(form["code_challenge_method"] == "S256", "PAR: expected S256 PKCE")
        precondition(form["redirect_uri"] != nil, "PAR: missing redirect_uri")
        guard case let .arr(details)? = try? JsonValue.parse(form["authorization_details"] ?? ""),
              case let .str(type)? = details[0]["type"], type == "openid_credential"
        else { preconditionFailure("PAR: bad authorization_details") }
        authCodeChallenge = form["code_challenge"]
        parRequestUri = "urn:ietf:params:oauth:request_uri:mock-\(form["state"] ?? "")"
        return HttpResponse(
            status: 201,
            headers: [("Content-Type", "application/json")],
            body: [UInt8](#"{"request_uri":"\#(parRequestUri!)","expires_in":90}"#.utf8)
        )
    }

    private func handleAuthorize(_ request: HttpRequest) -> HttpResponse {
        let query = request.url.contains("?") ? String(request.url.split(separator: "?", maxSplits: 1)[1]) : ""
        let params = parseForm(query)
        precondition(params["client_id"] != nil, "authorize: missing client_id")
        precondition(params["request_uri"] == parRequestUri, "authorize: unknown request_uri")
        return HttpResponse(status: 302, headers: [("Location", "wallet://cb?code=\(authCode)&state=...")], body: [])
    }

    private func handleToken(_ request: HttpRequest) async throws -> HttpResponse {
        let form = parseForm(String(bytes: request.body ?? [], encoding: .utf8) ?? "")
        let nonce = try await verifyDpop(request, htm: "POST", htu: "\(issuer)/token", accessToken: nil)

        switch form["grant_type"] {
        case grantPreAuthorized:
            precondition(form["pre-authorized_code"] == preAuthCode, "wrong pre-auth code")
            precondition(form["tx_code"] == "1234", "wrong tx_code")
        case "authorization_code":
            precondition(form["code"] == authCode, "wrong authorization code")
            let verifier = form["code_verifier"] ?? ""
            let computed = Base64Url.encode(sha256([UInt8](verifier.utf8)))
            precondition(computed == authCodeChallenge, "PKCE verification failed")
        case "refresh_token":
            precondition(form["refresh_token"] == issuedRefreshToken, "wrong refresh_token")
        default:
            preconditionFailure("unsupported grant_type \(form["grant_type"] ?? "nil")")
        }
        if nonce == nil {
            return HttpResponse(
                status: 400,
                headers: [("DPoP-Nonce", "dpop-nonce-token"), ("Content-Type", "application/json")],
                body: [UInt8](#"{"error":"use_dpop_nonce"}"#.utf8)
            )
        }
        seenDpopNonceRetry = true
        accessToken = "ACCESS-token-123"
        cNonce = "c-nonce-xyz"
        issuedRefreshToken = "REFRESH-token-5678"
        var authDetails = ""
        if let ids = credentialIdentifiers {
            let idList = ids.map { "\"\($0)\"" }.joined(separator: ",")
            authDetails = #","authorization_details":[{"type":"openid_credential","credential_configuration_id":"eu.europa.ec.eudi.pid.1","credential_identifiers":[\#(idList)]}]"#
        }
        return ok(#"{"access_token":"\#(accessToken!)","token_type":"DPoP","expires_in":3600,"refresh_token":"\#(issuedRefreshToken!)","c_nonce":"\#(cNonce!)"\#(authDetails)}"#)
    }

    private var issuedRefreshToken: String?

    /// When set, the issuer serves this JWT (as `application/jwt`) to wallets whose Accept allows it.
    public func setSignedMetadata(_ jws: String) { signedMetadata = jws }
    private var signedMetadata: String?

    /// The `Accept` the wallet sent on the last metadata GET — lets tests assert §12.2.2 negotiation.
    public private(set) var lastMetadataAccept: String?

    /// Content-negotiated metadata (OpenID4VCI §12.2.2): a signed JWT when the wallet accepts
    /// `application/jwt` and this issuer signs; otherwise the unsigned JSON document.
    private func handleIssuerMetadata(_ request: HttpRequest) -> HttpResponse {
        let accept = request.headers.first { $0.0.caseInsensitiveCompare("Accept") == .orderedSame }?.1
            ?? "application/json"
        lastMetadataAccept = accept
        if let jwt = signedMetadata, accept.contains("application/jwt") {
            return HttpResponse(status: 200, headers: [("Content-Type", "application/jwt")], body: [UInt8](jwt.utf8))
        }
        return ok(issuerMetadata())
    }

    private func handleNonce() -> HttpResponse {
        ok(#"{"c_nonce":"\#(cNonce ?? "c-nonce-xyz")"}"#)
    }

    private func handleDeferred(_ request: HttpRequest) async throws -> HttpResponse {
        guard let token = accessToken else { return HttpResponse(status: 401, headers: [], body: [UInt8]("no token".utf8)) }
        precondition(request.headers.contains { $0.0 == "Authorization" && $0.1 == "DPoP \(token)" }, "bad auth")
        _ = try await verifyDpop(request, htm: "POST", htu: "\(issuer)/deferred_credential", accessToken: token)

        // §9.1: the Deferred Credential Request is encrypted exactly like the Credential endpoint.
        let contentType = request.headers.first { $0.0.caseInsensitiveCompare("Content-Type") == .orderedSame }?.1
        let raw = String(bytes: request.body ?? [], encoding: .utf8) ?? ""
        let plaintext: String
        if contentType?.hasPrefix("application/jwt") == true {
            seenEncryptedRequest = true
            plaintext = String(bytes: try requestEncKey.decrypt(raw), encoding: .utf8) ?? ""
        } else {
            plaintext = raw
        }
        guard case .obj = try? JsonValue.parse(plaintext) else { preconditionFailure("bad deferred request body") }
        let body = try JsonValue.parse(plaintext)
        let responseEnc = body["credential_response_encryption"]

        deferredPollCount += 1
        // First poll: §9.2 re-deferral (HTTP 202 + interval + transaction_id); second poll: issue.
        if deferredPollCount < 2 {
            return try respond(#"{"transaction_id":"tx-1","interval":42}"#, responseEnc, status: 202)
        }
        let cred = try await issueSdJwtVc(holderKey: deferredHolderKey!)
        return try respond(#"{"credentials":[{"credential":"\#(cred)"}]}"#, responseEnc)
    }

    private func handleNotification(_ request: HttpRequest) throws -> HttpResponse {
        guard let token = accessToken else { return HttpResponse(status: 401, headers: [], body: [UInt8]("no token".utf8)) }
        precondition(request.headers.contains { $0.0 == "Authorization" && $0.1 == "DPoP \(token)" }, "bad auth")
        guard case let .obj(entries)? = try? JsonValue.parse(String(bytes: request.body ?? [], encoding: .utf8) ?? ""),
              case let .str(nid)? = JsonValue.obj(entries)["notification_id"],
              case let .str(ev)? = JsonValue.obj(entries)["event"] else {
            preconditionFailure("bad notification body")
        }
        seenNotification = (nid, ev)
        return HttpResponse(status: 204, headers: [], body: [])
    }

    private func handleCredential(_ request: HttpRequest) async throws -> HttpResponse {
        guard let token = accessToken else {
            return HttpResponse(status: 401, headers: [], body: [UInt8]("no token".utf8))
        }
        precondition(request.headers.contains { $0.0 == "Authorization" && $0.1 == "DPoP \(token)" }, "bad auth")
        _ = try await verifyDpop(request, htm: "POST", htu: "\(issuer)/credential", accessToken: token)

        // §10: an encrypted Credential Request arrives as application/jwt, encrypted to our request key.
        let contentType = request.headers.first { $0.0.caseInsensitiveCompare("Content-Type") == .orderedSame }?.1
        let raw = String(bytes: request.body ?? [], encoding: .utf8) ?? ""
        let plaintext: String
        if contentType?.hasPrefix("application/jwt") == true {
            seenEncryptedRequest = true
            if case let .obj(hdr)? = try? JsonValue.parse(try Base64Url.decodeToString(String(raw.split(separator: ".")[0]))),
               case let .str(k)? = JsonValue.obj(hdr)["kid"] {
                seenRequestKid = k
            }
            plaintext = String(bytes: try requestEncKey.decrypt(raw), encoding: .utf8) ?? ""
        } else {
            plaintext = raw
        }

        guard case let .obj(entries)? = try? JsonValue.parse(plaintext) else {
            preconditionFailure("bad credential request body")
        }
        let body = JsonValue.obj(entries)
        if case let .str(id)? = body["credential_identifier"] { seenCredentialIdentifier = id } else { seenCredentialIdentifier = nil }
        if case let .str(cfg)? = body["credential_configuration_id"] { seenConfigurationId = cfg } else { seenConfigurationId = nil }
        // §8.2: exactly one of the two identifies the requested Credential Dataset.
        precondition((seenCredentialIdentifier == nil) != (seenConfigurationId == nil),
                     "Credential Request must carry exactly one of credential_identifier / credential_configuration_id")

        // The wallet's response-encryption key, when it asked for one (§8.2).
        let responseEncEarly = body["credential_response_encryption"]

        // §8.2.1.3 attestation proof type: exactly one Key Attestation JWT, no per-key proof of possession.
        if case let .arr(attestation)? = body["proofs"]?["attestation"], case let .str(attestationJwt)? = attestation.first {
            seenAttestationProof = attestationJwt
            let attClaims = try JsonValue.parse(String(decoding: try Jws.parse(attestationJwt).payloadBytes, as: UTF8.self))
            guard case let .str(nonce)? = attClaims["nonce"], nonce == cNonce else { preconditionFailure("attestation nonce must equal the c_nonce") }
            guard case let .arr(keyJwks)? = attClaims["attested_keys"] else { preconditionFailure("attestation missing attested_keys") }
            var creds: [String] = []
            for jwk in keyJwks {
                guard let key = JwkEc.fromJson(jwk) else { continue }
                creds.append(#"{"credential":"\#(try await issueSdJwtVc(holderKey: key))"}"#)
            }
            seenProofCount = creds.count
            return try respond(#"{"credentials":[\#(creds.joined(separator: ","))],"notification_id":"n-1"}"#, responseEncEarly)
        }

        guard case let .arr(jwts)? = body["proofs"]?["jwt"], !jwts.isEmpty else {
            preconditionFailure("no proof jwt")
        }
        seenProofCount = jwts.count
        if case let .str(first) = jwts[0], case let .str(ka)? = (try? Jws.parse(first))?.header["key_attestation"] {
            seenKeyAttestation = ka
        }

        // The wallet's response-encryption key, when it asked for one (§8.2).
        let responseEnc = body["credential_response_encryption"]

        if deferMode, case let .str(first) = jwts[0] {
            // Defer (§8.3): verify the proof, remember the holder key, return a transaction_id + interval.
            deferredHolderKey = try await verifyKeyProof(first)
            return try respond(#"{"transaction_id":"tx-1","interval":300,"notification_id":"n-1"}"#, responseEnc, status: 202)
        }

        // One credential per proof (batch issuance), each bound to that proof's holder key.
        var creds: [String] = []
        for j in jwts {
            guard case let .str(proofJwt) = j else { continue }
            let holderKey = try await verifyKeyProof(proofJwt)
            creds.append(#"{"credential":"\#(try await issueSdJwtVc(holderKey: holderKey))"}"#)
        }
        return try respond(#"{"credentials":[\#(creds.joined(separator: ","))],"notification_id":"n-1"}"#, responseEnc)
    }

    /// Encrypts the Credential Response to the wallet's `jwk` when it requested encryption (§8.3 / §10).
    private func respond(_ json: String, _ responseEnc: JsonValue?, status: Int = 200) throws -> HttpResponse {
        guard let responseEnc, let jwk = responseEnc["jwk"] else {
            return HttpResponse(status: status, headers: [("Content-Type", "application/json")], body: [UInt8](json.utf8))
        }
        guard case let .str(alg)? = jwk["alg"], alg == "ECDH-ES" else {
            preconditionFailure("§10 requires alg on the chosen JWK")
        }
        guard let recipient = JwkEc.fromJson(jwk) else { preconditionFailure("bad response-encryption jwk") }
        guard case let .str(encId)? = responseEnc["enc"], let enc = JweEnc(rawValue: encId) else {
            preconditionFailure("bad enc")
        }
        seenResponseEnc = enc.rawValue
        let jwe = try Jwe.encryptEcdhEs(plaintext: [UInt8](json.utf8), recipient: recipient, enc: enc)
        return HttpResponse(status: status, headers: [("Content-Type", "application/jwt")], body: [UInt8](jwe.utf8))
    }

    /// Verifies a DPoP proof; returns its `nonce` claim (nil if absent). Fails on any invalidity.
    private func verifyDpop(_ request: HttpRequest, htm: String, htu: String, accessToken: String?) async throws -> String? {
        guard let dpop = request.headers.first(where: { $0.0 == "DPoP" })?.1 else {
            preconditionFailure("missing DPoP header")
        }
        let jws = try Jws.parse(dpop)
        guard case let .str(typ)? = jws.header["typ"], typ == "dpop+jwt" else { preconditionFailure("bad DPoP typ") }
        guard let jwk = jws.header["jwk"], let key = JwkEc.fromJson(jwk) else { preconditionFailure("bad DPoP jwk") }
        precondition(jws.verify(key: key, expected: .es256), "DPoP signature invalid")

        guard let claims = try? JsonValue.parse(String(bytes: jws.payloadBytes, encoding: .utf8) ?? "") else {
            preconditionFailure("bad DPoP payload")
        }
        guard case let .str(m)? = claims["htm"], m == htm else { preconditionFailure("DPoP htm mismatch") }
        guard case let .str(u)? = claims["htu"], u == htu else { preconditionFailure("DPoP htu mismatch") }
        guard case .str? = claims["jti"] else { preconditionFailure("DPoP jti missing") }
        if let accessToken {
            let expectedAth = Base64Url.encode(sha256([UInt8](accessToken.utf8)))
            guard case let .str(ath)? = claims["ath"], ath == expectedAth else { preconditionFailure("DPoP ath mismatch") }
        }
        if case let .str(nonce)? = claims["nonce"] { return nonce }
        return nil
    }

    private func verifyKeyProof(_ proofJwt: String) async throws -> EcPublicKey {
        let jws = try Jws.parse(proofJwt)
        guard case let .str(typ)? = jws.header["typ"], typ == "openid4vci-proof+jwt" else {
            preconditionFailure("wrong proof typ")
        }
        guard let jwk = jws.header["jwk"], let key = JwkEc.fromJson(jwk) else { preconditionFailure("bad proof jwk") }
        precondition(jws.verify(key: key, expected: .es256), "proof signature invalid")
        guard let claims = try? JsonValue.parse(String(bytes: jws.payloadBytes, encoding: .utf8) ?? "") else {
            preconditionFailure("bad proof payload")
        }
        guard case let .str(aud)? = claims["aud"], aud == issuer else { preconditionFailure("proof aud mismatch") }
        guard case let .str(nonce)? = claims["nonce"], nonce == cNonce else { preconditionFailure("proof nonce mismatch") }
        return key
    }

    private func issueSdJwtVc(holderKey: EcPublicKey) async throws -> String {
        let signer = SecureAreaJwsSigner(area: area, key: issuerKey.handle, algorithm: .es256)
        var n = 0
        let salts: () -> String = { n += 1; return "salt-\(n)" }
        let sdJwt = try await SdJwtIssuer(saltProvider: salts).issue(
            signer: signer, holderKey: holderKey, typ: "dc+sd-jwt", decoysPerSdStruct: 2
        ) { b in
            b.claim("iss", self.issuer)
            b.claim("vct", "eu.europa.ec.eudi.pid.1")
            b.claim("iat", self.now)
            b.claim("exp", self.now + 86_400)
            b.sd("family_name", "Doe")
            b.sd("given_name", "John")
            b.sd("birthdate", "1990-01-01")
        }
        return sdJwt.serialize()
    }

    private func issuerMetadata() -> String {
        let encryption = encryptionSupported ? requestEncryptionJson() + responseEncryptionJson() : ""
        let keyAttReq = requiresKeyAttestation ? #","key_attestations_required":{"key_storage":["iso_18045_high"]}"# : ""
        let attestation = supportsAttestationProof ? #","attestation":{"proof_signing_alg_values_supported":["ES256"]\#(keyAttReq)}"# : ""
        return """
        {"credential_issuer":"\(issuer)",
         \(encryption)"credential_endpoint":"\(issuer)/credential",
         "nonce_endpoint":"\(issuer)/nonce",
         "deferred_credential_endpoint":"\(issuer)/deferred_credential",
         "notification_endpoint":"\(issuer)/notification",
         "authorization_servers":["\(issuer)"],
         "display":[{"name":"Hopae Test Issuer"}],
         "credential_configurations_supported":{
           "eu.europa.ec.eudi.pid.1":{"format":"dc+sd-jwt","vct":"eu.europa.ec.eudi.pid.1",
             "display":[{"name":"Personal ID","logo":{"uri":"https://logo.example/pid.png"},"background_color":"#123456"}],
             "proof_types_supported":{"jwt":{"proof_signing_alg_values_supported":["ES256"]\(keyAttReq)}\(attestation)}}}}
        """
    }

    private func asMetadata() -> String {
        """
        {"issuer":"\(issuer)","token_endpoint":"\(issuer)/token",
         "authorization_endpoint":"\(issuer)/authorize",
         "pushed_authorization_request_endpoint":"\(issuer)/par",
         "code_challenge_methods_supported":["S256"],
         "dpop_signing_alg_values_supported":["ES256"]}
        """
    }

    private func jwtVcIssuerMetadata() -> String {
        let jwk = JwkEc.toJson(issuerKey.publicKey).serialize()
        return #"{"issuer":"\#(issuer)","jwks":{"keys":[\#(jwk)]}}"#
    }

    private func ok(_ body: String) -> HttpResponse {
        HttpResponse(status: 200, headers: [("Content-Type", "application/json")], body: [UInt8](body.utf8))
    }

    private func parseForm(_ form: String) -> [String: String] {
        var out: [String: String] = [:]
        for pair in form.split(separator: "&") {
            let kv = pair.split(separator: "=", maxSplits: 1)
            guard kv.count == 2 else { continue }
            let k = String(kv[0]).removingPercentEncoding ?? String(kv[0])
            let v = String(kv[1]).removingPercentEncoding ?? String(kv[1])
            out[k] = v
        }
        return out
    }
}
