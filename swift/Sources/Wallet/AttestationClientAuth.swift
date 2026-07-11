import OpenID4VCI
import SdJwt
import WalletAPI

/// HAIP attestation-based client authentication, wired from `WalletPorts.walletAttestation`. Holds one
/// persistent wallet instance key (created in the `secureArea` and remembered via `storage`; bound into
/// every WUA's `cnf`) and, on each request, produces the `OAuth-Client-Attestation[-PoP]` headers.
///
/// HAIP §4.4.1 (unlinkability): a WUA is fetched fresh per authorization server and never reused across
/// issuers — `wuaByAudience` caches one WUA per `aud` so a single issuer's PAR + token reuse it, but a
/// different issuer always triggers a fresh fetch. The `sub` is the (non-instance-unique) `clientId`.
///
/// Residual (documented): the instance key is persistent, so the WUA `cnf` is the same across issuers —
/// colluding issuers could still correlate. Full unlinkability needs a per-use key batch (a later refinement).
final class AttestationClientAuth: ClientAuthProvider {
    let clientId: String
    private let provider: any WalletAttestationProvider
    private let secureArea: any SecureArea
    private let storage: any StorageDriver
    private let rng: any Rng
    private let clock: () -> Int64

    private var instance: KeyInfo?
    private var wuaByAudience: [String: String] = [:]

    init(clientId: String, provider: any WalletAttestationProvider, secureArea: any SecureArea,
         storage: any StorageDriver, rng: any Rng, clock: @escaping () -> Int64) {
        self.clientId = clientId
        self.provider = provider
        self.secureArea = secureArea
        self.storage = storage
        self.rng = rng
        self.clock = clock
    }

    func headers(audience: String) async throws -> [(String, String)] {
        let key = try await instanceKey()
        let wua = try await walletAttestation(audience: audience, key: key)
        let pop = ClientAttestationPop(
            signer: SecureAreaJwsSigner(area: secureArea, key: key.handle, algorithm: key.algorithm),
            clientId: clientId, rng: rng, now: clock)
        return try await WalletClientAuth(clientId: clientId, attestationJwt: wua, pop: pop).headers(audience: audience)
    }

    /// The persistent wallet instance key: created once, its alias remembered so it survives restarts.
    private func instanceKey() async throws -> KeyInfo {
        if let instance { return instance }
        let info: KeyInfo
        if let stored = try await storage.get(collection: Self.storeCollection, key: Self.storeKey) {
            let handle = KeyHandle(secureArea: secureArea.id, alias: String(decoding: stored, as: UTF8.self))
            info = KeyInfo(handle: handle, algorithm: .es256, publicKey: try await secureArea.publicKey(key: handle))
        } else {
            let created = try await secureArea.createKey(spec: KeySpec(secureArea: secureArea.id))
            try await storage.put(collection: Self.storeCollection, key: Self.storeKey, value: [UInt8](created.handle.alias.utf8))
            info = created
        }
        instance = info
        return info
    }

    private func walletAttestation(audience: String, key: KeyInfo) async throws -> String {
        if let cached = wuaByAudience[audience] { return cached }
        let wua = try await provider.walletAttestation(keyInfo: key)
        wuaByAudience[audience] = wua
        return wua
    }

    private static let storeCollection = "wallet-provider"
    private static let storeKey = "instance-key"
}
