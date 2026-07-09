import Foundation
import SdJwt

/* OpenID4VCI 1.0 wire models, parsed from the SDK's own JsonValue. */

private extension JsonValue {
    func string(_ name: String) -> String? {
        if case let .str(s)? = self[name] { return s }
        return nil
    }

    func requireString(_ name: String, _ where_: String) throws -> String {
        guard let s = string(name) else { throw VciError.protocolError("\(where_): missing '\(name)'") }
        return s
    }

    func stringArray(_ name: String) -> [String]? {
        guard case let .arr(items)? = self[name] else { return nil }
        var out: [String] = []
        for item in items {
            guard case let .str(s) = item else { return nil }
            out.append(s)
        }
        return out
    }
}

/// Credential offer (OpenID4VCI §4.1).
public struct CredentialOffer {
    /// The Transaction Code input hints from a Credential Offer (OpenID4VCI §4.1.1). These describe how
    /// the wallet should render the code-entry screen; they are guidance, not a wire constraint, so the
    /// SDK never rejects a supplied code on their basis — `violations` lets the host surface a warning.
    public struct TxCodeSpec {
        public let length: Int?
        public let inputMode: String?
        public let description: String?

        public init(length: Int?, inputMode: String?, description: String?) {
            self.length = length
            self.inputMode = inputMode
            self.description = description
        }

        /// The ways `code` departs from these hints (empty = consistent). Advisory only: `input_mode`
        /// `numeric` means digits only, `text` accepts anything, and `length` is the expected character
        /// count. Never throws — a wallet may warn, or send the code regardless and let the issuer decide.
        public func violations(_ code: String) -> [String] {
            var out: [String] = []
            let mode = inputMode ?? "numeric" // §4.1.1: numeric is the default
            if mode == "numeric" && !code.allSatisfy(\.isNumber) {
                out.append("transaction code must contain only digits (input_mode=numeric)")
            }
            if let length, code.count != length {
                out.append("transaction code should be \(length) characters, got \(code.count)")
            }
            return out
        }
    }

    public let credentialIssuer: String
    public let credentialConfigurationIds: [String]
    public let preAuthorizedCode: String?
    public let txCode: TxCodeSpec?
    public let authorizationCodeIssuerState: String?

    public static func parse(_ json: String) throws -> CredentialOffer {
        guard let obj = try? JsonValue.parse(json), case .obj = obj else {
            throw VciError.invalidOffer("not an object")
        }
        return try fromObj(obj)
    }

    public static func fromObj(_ o: JsonValue) throws -> CredentialOffer {
        guard let issuer = o.string("credential_issuer") else {
            throw VciError.invalidOffer("missing credential_issuer")
        }
        guard let ids = o.stringArray("credential_configuration_ids") else {
            throw VciError.invalidOffer("missing credential_configuration_ids")
        }
        guard !ids.isEmpty else { throw VciError.invalidOffer("credential_configuration_ids is empty") }

        let grants = o["grants"]
        let preAuth = grants?["urn:ietf:params:oauth:grant-type:pre-authorized_code"]
        let authCode = grants?["authorization_code"]

        var txCode: TxCodeSpec?
        if case let .obj(entries)? = preAuth?["tx_code"] {
            let tx = JsonValue.obj(entries)
            var length: Int?
            if case let .numInt(n)? = tx["length"] { length = Int(n) }
            var inputMode: String?
            if case let .str(m)? = tx["input_mode"] { inputMode = m }
            var desc: String?
            if case let .str(d)? = tx["description"] { desc = d }
            txCode = TxCodeSpec(length: length, inputMode: inputMode, description: desc)
        }

        return CredentialOffer(
            credentialIssuer: issuer,
            credentialConfigurationIds: ids,
            preAuthorizedCode: preAuth?.string("pre-authorized_code"),
            txCode: txCode,
            authorizationCodeIssuerState: authCode?.string("issuer_state")
        )
    }
}

/// Credential issuer metadata (OpenID4VCI §11.2).
/// The issuer's `credential_response_encryption` metadata (OpenID4VCI §12.2.4): which JWE algorithms it
/// can encrypt Credential Responses with, and whether encryption is mandatory.
public struct ResponseEncryptionMetadata {
    public let algValuesSupported: [String]
    public let encValuesSupported: [String]
    public let encryptionRequired: Bool

    static func fromObj(_ o: JsonValue) -> ResponseEncryptionMetadata {
        var required = false
        if case let .bool(b)? = o["encryption_required"] { required = b }
        return ResponseEncryptionMetadata(
            algValuesSupported: o.stringArray("alg_values_supported") ?? [],
            encValuesSupported: o.stringArray("enc_values_supported") ?? [],
            encryptionRequired: required)
    }
}

/// The issuer's `credential_request_encryption` metadata: the public keys a Credential Request may be
/// encrypted to. §8.2 makes request encryption mandatory whenever a `credential_response_encryption`
/// object is sent, so that an attacker cannot substitute the wallet's response-encryption key.
public struct RequestEncryptionMetadata {
    /// Raw JWKs — `alg` (§10 requires it) and `kid` matter, so the parsed EC key alone is not enough.
    public let jwks: [JsonValue]
    public let encValuesSupported: [String]
    public let encryptionRequired: Bool

    static func fromObj(_ o: JsonValue) -> RequestEncryptionMetadata {
        var required = false
        if case let .bool(b)? = o["encryption_required"] { required = b }
        var keys: [JsonValue] = []
        if case let .arr(items)? = o["jwks"]?["keys"] {
            keys = items.filter { if case .obj = $0 { return true }; return false }
        }
        return RequestEncryptionMetadata(
            jwks: keys,
            encValuesSupported: o.stringArray("enc_values_supported") ?? [],
            encryptionRequired: required)
    }
}

public struct CredentialIssuerMetadata {
    public let credentialIssuer: String
    public let credentialEndpoint: String
    public let nonceEndpoint: String?
    public let deferredCredentialEndpoint: String?
    public let notificationEndpoint: String?
    public let authorizationServers: [String]
    public let credentialConfigurationsSupported: [String: CredentialConfiguration]
    /// Issuer display name (first `display` entry), if advertised.
    public let issuerDisplayName: String?
    public let credentialResponseEncryption: ResponseEncryptionMetadata?
    public let credentialRequestEncryption: RequestEncryptionMetadata?

    public static func fromObj(_ o: JsonValue) throws -> CredentialIssuerMetadata {
        let issuer = try o.requireString("credential_issuer", "issuer metadata")
        var configs: [String: CredentialConfiguration] = [:]
        if case let .obj(entries)? = o["credential_configurations_supported"] {
            for (id, v) in entries {
                guard case .obj = v else { throw VciError.metadata("config '\(id)' not an object") }
                configs[id] = CredentialConfiguration.fromObj(v)
            }
        }
        var issuerDisplayName: String?
        if case let .arr(displays)? = o["display"], let first = displays.first, case let .str(n)? = first["name"] {
            issuerDisplayName = n
        }
        return CredentialIssuerMetadata(
            credentialIssuer: issuer,
            credentialEndpoint: try o.requireString("credential_endpoint", "issuer metadata"),
            nonceEndpoint: o.string("nonce_endpoint"),
            deferredCredentialEndpoint: o.string("deferred_credential_endpoint"),
            notificationEndpoint: o.string("notification_endpoint"),
            authorizationServers: o.stringArray("authorization_servers") ?? [issuer],
            credentialConfigurationsSupported: configs,
            issuerDisplayName: issuerDisplayName,
            credentialResponseEncryption: o["credential_response_encryption"].map { ResponseEncryptionMetadata.fromObj($0) },
            credentialRequestEncryption: o["credential_request_encryption"].map { RequestEncryptionMetadata.fromObj($0) }
        )
    }
}

public struct CredentialConfiguration {
    public let format: String
    public let vct: String?
    public let docType: String?
    public let proofSigningAlgs: [String]
    public let scope: String?
    /// From the first `display` entry — for wallet UI.
    public let displayName: String?
    public let logoUri: String?
    public let backgroundColor: String?

    public init(format: String, vct: String?, docType: String?, proofSigningAlgs: [String], scope: String?,
                displayName: String? = nil, logoUri: String? = nil, backgroundColor: String? = nil) {
        self.format = format; self.vct = vct; self.docType = docType
        self.proofSigningAlgs = proofSigningAlgs; self.scope = scope
        self.displayName = displayName; self.logoUri = logoUri; self.backgroundColor = backgroundColor
    }

    public static func fromObj(_ o: JsonValue) -> CredentialConfiguration {
        var proofAlgs: [String] = []
        if case let .arr(items)? = o["proof_types_supported"]?["jwt"]?["proof_signing_alg_values_supported"] {
            proofAlgs = items.compactMap { if case let .str(s) = $0 { return s } else { return nil } }
        }
        var format = ""
        if case let .str(f)? = o["format"] { format = f }
        var vct: String?
        if case let .str(v)? = o["vct"] { vct = v }
        var docType: String?
        if case let .str(d)? = o["doctype"] { docType = d }
        var scope: String?
        if case let .str(s)? = o["scope"] { scope = s }
        var displayName: String?, logoUri: String?, backgroundColor: String?
        if case let .arr(displays)? = o["display"], let first = displays.first {
            if case let .str(n)? = first["name"] { displayName = n }
            if case let .str(u)? = first["logo"]?["uri"] { logoUri = u }
            if case let .str(c)? = first["background_color"] { backgroundColor = c }
        }
        return CredentialConfiguration(format: format, vct: vct, docType: docType, proofSigningAlgs: proofAlgs,
                                       scope: scope, displayName: displayName, logoUri: logoUri, backgroundColor: backgroundColor)
    }
}

/// Authorization server metadata (RFC 8414) — the fields we use.
public struct AuthorizationServerMetadata {
    public let issuer: String
    public let tokenEndpoint: String
    public let pushedAuthorizationRequestEndpoint: String?
    public let authorizationEndpoint: String?
    public let dpopSigningAlgValuesSupported: [String]

    public static func fromObj(_ o: JsonValue) throws -> AuthorizationServerMetadata {
        AuthorizationServerMetadata(
            issuer: try o.requireString("issuer", "AS metadata"),
            tokenEndpoint: try o.requireString("token_endpoint", "AS metadata"),
            pushedAuthorizationRequestEndpoint: o.string("pushed_authorization_request_endpoint"),
            authorizationEndpoint: o.string("authorization_endpoint"),
            dpopSigningAlgValuesSupported: o.stringArray("dpop_signing_alg_values_supported") ?? []
        )
    }
}

public struct TokenResponse {
    public let accessToken: String
    public let tokenType: String
    public let cNonce: String?
    public let expiresIn: Int64?
    /// OAuth 2.0 refresh token (RFC 6749 §5.1) — enables reissuance without re-authorization.
    public let refreshToken: String?

    public static func fromObj(_ o: JsonValue) throws -> TokenResponse {
        var cNonce: String?
        if case let .str(n)? = o["c_nonce"] { cNonce = n }
        var expiresIn: Int64?
        if case let .numInt(e)? = o["expires_in"] { expiresIn = e }
        var refreshToken: String?
        if case let .str(r)? = o["refresh_token"] { refreshToken = r }
        return TokenResponse(
            accessToken: try o.requireString("access_token", "token response"),
            tokenType: try o.requireString("token_type", "token response"),
            cNonce: cNonce,
            expiresIn: expiresIn,
            refreshToken: refreshToken
        )
    }
}

public struct IssuedCredential {
    public let format: String
    public let credential: String
}

public struct CredentialResponse {
    public let credentials: [IssuedCredential]
    public let transactionId: String?
    public let notificationId: String?
    /// Context for follow-ups (deferred poll, notification, reissuance) — set by the client, not parsed.
    public let accessToken: String?
    public let credentialIssuer: String?
    public let requestedFormat: String
    /// Refresh token + config id — persist these to reissue (renew) the credential later.
    public let refreshToken: String?
    public let configurationId: String?

    public init(credentials: [IssuedCredential], transactionId: String?, notificationId: String?,
                accessToken: String? = nil, credentialIssuer: String? = nil, requestedFormat: String = "dc+sd-jwt",
                refreshToken: String? = nil, configurationId: String? = nil) {
        self.credentials = credentials
        self.transactionId = transactionId
        self.notificationId = notificationId
        self.accessToken = accessToken
        self.credentialIssuer = credentialIssuer
        self.requestedFormat = requestedFormat
        self.refreshToken = refreshToken
        self.configurationId = configurationId
    }

    /// True when the issuer deferred issuance (returned a transaction_id, no credential yet).
    public var isDeferred: Bool { credentials.isEmpty && transactionId != nil }

    /// True when the issuer granted a refresh token, so `reissue` can renew the credential later.
    public var canReissue: Bool { refreshToken != nil && credentialIssuer != nil && configurationId != nil }

    func withContext(accessToken: String?, credentialIssuer: String?, requestedFormat: String,
                     refreshToken: String? = nil, configurationId: String? = nil) -> CredentialResponse {
        CredentialResponse(credentials: credentials, transactionId: transactionId, notificationId: notificationId,
                           accessToken: accessToken, credentialIssuer: credentialIssuer, requestedFormat: requestedFormat,
                           refreshToken: refreshToken, configurationId: configurationId)
    }

    public static func fromObj(_ o: JsonValue, requestedFormat: String) -> CredentialResponse {
        var creds: [IssuedCredential] = []
        if case let .arr(items)? = o["credentials"] {
            for item in items {
                if case let .str(c)? = item["credential"] {
                    creds.append(IssuedCredential(format: requestedFormat, credential: c))
                }
            }
        }
        var txId: String?
        if case let .str(t)? = o["transaction_id"] { txId = t }
        var notifId: String?
        if case let .str(n)? = o["notification_id"] { notifId = n }
        return CredentialResponse(credentials: creds, transactionId: txId, notificationId: notifId, requestedFormat: requestedFormat)
    }
}
