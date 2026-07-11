import Foundation
import SdJwt
import WalletAPI

/// Produces a device/app integrity token for wallet-instance registration, bound to the wallet provider's
/// challenge `nonce`. On Apple platforms this wraps App Attest / DeviceCheck. An internal seam of the
/// reference adapter, not an SDK port — a deployment with its own wallet-provider implements its own
/// `WalletAttestationProvider` and handles integrity however its backend expects.
public protocol IntegrityTokenProvider: Sendable {
    func integrityToken(nonce: String) async throws -> String
}

/// Dev fallback: emits the `dev-integrity:<nonce>` token the reference wallet-provider backend accepts
/// without real attestation. For local development, tests, and the demo fallback path. Not for production.
public struct DevIntegrityTokenProvider: IntegrityTokenProvider {
    public init() {}
    public func integrityToken(nonce: String) async throws -> String { "dev-integrity:\(nonce)" }
}

public enum WalletProviderError: Error {
    case http(status: Int, body: String)
    case missingField(String)
    case malformedResponse
}

/// Reference `WalletAttestationProvider` adapter that talks to the SDK's `wallet-provider/` backend
/// (`GET /nonce`, `POST /wallet-instances`, `POST /wallet-attestation`, `POST /key-attestation`). A plain
/// composition of the SDK ports — the injected `http` transport and `secureArea` (which signs the
/// instance-key proof of possession) — plus a platform `integrity` token source; injected into
/// `WalletPorts.walletAttestation`. A deployment with a different wallet-provider swaps its own at the port.
///
/// An `actor` because it caches the registered `instanceId`; the SDK-owned wallet instance key (bound into
/// the WUA `cnf`) is passed to each call.
public actor WalletProviderAttestation: WalletAttestationProvider {
    private let issuer: String
    private let http: any HttpTransport
    private let secureArea: any SecureArea
    private let integrity: any IntegrityTokenProvider
    private let clientId: String
    private let clock: @Sendable () -> Int64
    private var instanceId: String?

    public init(baseUrl: String, http: any HttpTransport, secureArea: any SecureArea,
                integrity: any IntegrityTokenProvider, clientId: String,
                clock: @escaping @Sendable () -> Int64 = { Int64(Date().timeIntervalSince1970) }) {
        self.issuer = baseUrl.hasSuffix("/") ? String(baseUrl.dropLast()) : baseUrl
        self.http = http
        self.secureArea = secureArea
        self.integrity = integrity
        self.clientId = clientId
        self.clock = clock
    }

    public func walletAttestation(keyInfo: KeyInfo) async throws -> String {
        let id = try await registeredInstance(keyInfo)
        let body = JsonValue.obj([
            ("instanceId", .str(id)),
            ("clientId", .str(clientId)),
            ("pop", .str(try await instancePop(keyInfo, nonce: fetchNonce()))),
        ])
        return try string(await postJson("\(issuer)/wallet-attestation", body), "wallet_attestation")
    }

    public func keyAttestation(keys: [KeyInfo], nonce: String?) async throws -> String {
        var entries: [(String, JsonValue)] = [("attestedKeys", .arr(keys.map { JwkEc.toJson($0.publicKey) }))]
        if let nonce { entries.append(("nonce", .str(nonce))) }
        return try string(await postJson("\(issuer)/key-attestation", .obj(entries)), "key_attestation")
    }

    /// Registers the instance once (nonce → integrity token → `POST /wallet-instances`), caching its id.
    private func registeredInstance(_ keyInfo: KeyInfo) async throws -> String {
        if let instanceId { return instanceId }
        let nonce = try await fetchNonce()
        let body = JsonValue.obj([
            ("instanceKey", JwkEc.toJson(keyInfo.publicKey)),
            ("integrityToken", .str(try await integrity.integrityToken(nonce: nonce))),
            ("nonce", .str(nonce)),
        ])
        let id = try string(await postJson("\(issuer)/wallet-instances", body), "instanceId")
        instanceId = id
        return id
    }

    private func fetchNonce() async throws -> String {
        try string(parse(await http.execute(HttpRequest(method: .get, url: "\(issuer)/nonce"))), "nonce")
    }

    /// Proof of possession of the instance key to the wallet provider: `{ aud: issuer, nonce, iat }`.
    private func instancePop(_ keyInfo: KeyInfo, nonce: String) async throws -> String {
        let header = JsonValue.obj([("typ", .str("wallet-provider-pop+jwt")), ("alg", .str(jwsAlg(keyInfo.algorithm)))])
        let claims = JsonValue.obj([("aud", .str(issuer)), ("nonce", .str(nonce)), ("iat", .numInt(clock()))])
        let signer = SecureAreaJwsSigner(area: secureArea, key: keyInfo.handle, algorithm: keyInfo.algorithm)
        return try await Jws.sign(header: header, payload: [UInt8](claims.serialize().utf8), signer: signer).compact()
    }

    private func postJson(_ url: String, _ body: JsonValue) async throws -> JsonValue {
        try parse(await http.execute(HttpRequest(
            method: .post, url: url,
            headers: [("Content-Type", "application/json")], body: [UInt8](body.serialize().utf8))))
    }

    private func parse(_ resp: HttpResponse) throws -> JsonValue {
        guard (200...299).contains(resp.status) else {
            throw WalletProviderError.http(status: resp.status, body: String(decoding: resp.body.prefix(200), as: UTF8.self))
        }
        return try JsonValue.parse(String(decoding: resp.body, as: UTF8.self))
    }

    private func string(_ json: JsonValue, _ key: String) throws -> String {
        guard case let .str(value)? = json[key] else { throw WalletProviderError.missingField(key) }
        return value
    }

    private func jwsAlg(_ alg: SigningAlgorithm) -> String {
        switch alg {
        case .es256: return "ES256"
        case .es384: return "ES384"
        case .es512: return "ES512"
        }
    }
}
