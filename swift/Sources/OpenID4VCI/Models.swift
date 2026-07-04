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
    public struct TxCodeSpec {
        public let length: Int?
        public let inputMode: String?
        public let description: String?
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
public struct CredentialIssuerMetadata {
    public let credentialIssuer: String
    public let credentialEndpoint: String
    public let nonceEndpoint: String?
    public let deferredCredentialEndpoint: String?
    public let authorizationServers: [String]
    public let credentialConfigurationsSupported: [String: CredentialConfiguration]

    public static func fromObj(_ o: JsonValue) throws -> CredentialIssuerMetadata {
        let issuer = try o.requireString("credential_issuer", "issuer metadata")
        var configs: [String: CredentialConfiguration] = [:]
        if case let .obj(entries)? = o["credential_configurations_supported"] {
            for (id, v) in entries {
                guard case .obj = v else { throw VciError.metadata("config '\(id)' not an object") }
                configs[id] = CredentialConfiguration.fromObj(v)
            }
        }
        return CredentialIssuerMetadata(
            credentialIssuer: issuer,
            credentialEndpoint: try o.requireString("credential_endpoint", "issuer metadata"),
            nonceEndpoint: o.string("nonce_endpoint"),
            deferredCredentialEndpoint: o.string("deferred_credential_endpoint"),
            authorizationServers: o.stringArray("authorization_servers") ?? [issuer],
            credentialConfigurationsSupported: configs
        )
    }
}

public struct CredentialConfiguration {
    public let format: String
    public let vct: String?
    public let docType: String?
    public let proofSigningAlgs: [String]
    public let scope: String?

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
        return CredentialConfiguration(format: format, vct: vct, docType: docType, proofSigningAlgs: proofAlgs, scope: scope)
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

    public static func fromObj(_ o: JsonValue) throws -> TokenResponse {
        var cNonce: String?
        if case let .str(n)? = o["c_nonce"] { cNonce = n }
        var expiresIn: Int64?
        if case let .numInt(e)? = o["expires_in"] { expiresIn = e }
        return TokenResponse(
            accessToken: try o.requireString("access_token", "token response"),
            tokenType: try o.requireString("token_type", "token response"),
            cNonce: cNonce,
            expiresIn: expiresIn
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
        return CredentialResponse(credentials: creds, transactionId: txId, notificationId: notifId)
    }
}
