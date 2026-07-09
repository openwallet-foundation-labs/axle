import Foundation
import OpenID4VCI
import SdJwt
import WalletAPI

/// Everything needed to resume a credential after issuance — deferred poll, reissue, notification —
/// across app restarts (assembly gap #3). Key material stays in the SecureArea; only handles serialize.
struct FollowUpContext {
    let credentialIssuer: String
    let configurationId: String
    let requestedFormat: String
    let accessToken: String?
    let refreshToken: String?
    let transactionId: String?
    let notificationId: String?
    let proofKeys: [KeyHandle]
    let dpopKey: KeyHandle
    let policy: CredentialPolicy

    /// A copy with a fresh `transaction_id` — the issuer rotates it on each still-deferred (202) response.
    func withTransactionId(_ transactionId: String?) -> FollowUpContext {
        FollowUpContext(credentialIssuer: credentialIssuer, configurationId: configurationId, requestedFormat: requestedFormat,
                        accessToken: accessToken, refreshToken: refreshToken, transactionId: transactionId,
                        notificationId: notificationId, proofKeys: proofKeys, dpopKey: dpopKey, policy: policy)
    }

    /// Reconstructs the vci `CredentialResponse` carrying the follow-up context (public init).
    func toCredentialResponse() -> CredentialResponse {
        CredentialResponse(credentials: [], transactionId: transactionId, notificationId: notificationId,
                           accessToken: accessToken, credentialIssuer: credentialIssuer, requestedFormat: requestedFormat,
                           refreshToken: refreshToken, configurationId: configurationId)
    }

    func encode() -> [UInt8] {
        let json = JsonValue.obj([
            ("credentialIssuer", .str(credentialIssuer)),
            ("configurationId", .str(configurationId)),
            ("requestedFormat", .str(requestedFormat)),
            ("accessToken", accessToken.map(JsonValue.str) ?? .null),
            ("refreshToken", refreshToken.map(JsonValue.str) ?? .null),
            ("transactionId", transactionId.map(JsonValue.str) ?? .null),
            ("notificationId", notificationId.map(JsonValue.str) ?? .null),
            ("proofKeys", .arr(proofKeys.map(handleJson))),
            ("dpopKey", handleJson(dpopKey)),
            ("batchSize", .numInt(Int64(policy.batchSize))),
            ("use", .str(policy.use == .rotate ? "rotate" : "oneTime")),
        ])
        return Array(json.serialize().utf8)
    }

    static func decode(_ bytes: [UInt8]) throws -> FollowUpContext {
        let o = try JsonValue.parse(String(decoding: bytes, as: UTF8.self))
        func str(_ k: String) -> String { if case let .str(s)? = o[k] { return s }; return "" }
        func strOrNil(_ k: String) -> String? { if case let .str(s)? = o[k] { return s }; return nil }
        var proofs: [KeyHandle] = []
        if case let .arr(items)? = o["proofKeys"] { proofs = items.map(keyHandle) }
        var batch: Int64 = 1
        if case let .numInt(n)? = o["batchSize"] { batch = n }
        return FollowUpContext(
            credentialIssuer: str("credentialIssuer"), configurationId: str("configurationId"),
            requestedFormat: str("requestedFormat"), accessToken: strOrNil("accessToken"),
            refreshToken: strOrNil("refreshToken"), transactionId: strOrNil("transactionId"),
            notificationId: strOrNil("notificationId"), proofKeys: proofs, dpopKey: keyHandle(o["dpopKey"] ?? .null),
            policy: CredentialPolicy(batchSize: Int(batch), use: str("use") == "oneTime" ? .oneTime : .rotate))
    }
}

private func handleJson(_ h: KeyHandle) -> JsonValue {
    .obj([("secureArea", .str(h.secureArea.value)), ("alias", .str(h.alias))])
}

private func keyHandle(_ v: JsonValue) -> KeyHandle {
    func s(_ k: String) -> String { if case let .str(x)? = v[k] { return x }; return "" }
    return KeyHandle(secureArea: SecureAreaId(s("secureArea")), alias: s("alias"))
}
