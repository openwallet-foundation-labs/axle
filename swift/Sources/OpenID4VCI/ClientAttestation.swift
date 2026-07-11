import Foundation
import SdJwt
import WalletAPI

/// Client Attestation PoP JWT builder (OAuth 2.0 Attestation-Based Client Authentication §4.2,
/// required by HAIP). Signed by the wallet instance key bound in the attestation's `cnf`; a fresh
/// PoP per request proves possession of that key to the `audience` (the authorization server).
public struct ClientAttestationPop {
    private let signer: any JwsSigner
    private let clientId: String
    private let rng: any Rng
    private let now: () -> Int64
    private let lifetimeSeconds: Int64

    public init(signer: any JwsSigner, clientId: String, rng: any Rng, now: @escaping () -> Int64, lifetimeSeconds: Int64 = 300) {
        self.signer = signer; self.clientId = clientId; self.rng = rng; self.now = now; self.lifetimeSeconds = lifetimeSeconds
    }

    public func pop(audience: String) async throws -> String {
        let header = JsonValue.obj([
            ("typ", .str("oauth-client-attestation-pop+jwt")),
            ("alg", .str(jwsAlgName(signer.algorithm))),
        ])
        let claims = JsonValue.obj([
            ("iss", .str(clientId)),
            ("aud", .str(audience)),
            ("iat", .numInt(now())),
            ("exp", .numInt(now() + lifetimeSeconds)),
            ("jti", .str(Base64Url.encode(rng.nextBytes(16)))),
        ])
        return try await Jws.sign(header: header, payload: [UInt8](claims.serialize().utf8), signer: signer).compact()
    }
}

/// Supplies HAIP attestation-based client-auth headers (`OAuth-Client-Attestation[-PoP]`) for a given
/// authorization-server `audience`. The wallet injects an implementation that fetches the WUA fresh per
/// issuer (HAIP §4.4.1 unlinkability — a WUA is never reused across authorization servers); a fixed
/// `WalletClientAuth` is the simplest case.
public protocol ClientAuthProvider {
    var clientId: String { get }
    func headers(audience: String) async throws -> [(String, String)]
}

/// Attestation-based client authentication (HAIP): pairs the wallet-provider-issued attestation JWT
/// with a per-request `ClientAttestationPop`. Attached to PAR and token requests as the
/// `OAuth-Client-Attestation` and `OAuth-Client-Attestation-PoP` headers.
public struct WalletClientAuth: ClientAuthProvider {
    public let clientId: String
    public let attestationJwt: String
    private let pop: ClientAttestationPop

    public init(clientId: String, attestationJwt: String, pop: ClientAttestationPop) {
        self.clientId = clientId; self.attestationJwt = attestationJwt; self.pop = pop
    }

    public func headers(audience: String) async throws -> [(String, String)] {
        [("OAuth-Client-Attestation", attestationJwt),
         ("OAuth-Client-Attestation-PoP", try await pop.pop(audience: audience))]
    }

    /// Builds client auth from a `WalletAttestationProvider` and the wallet instance key.
    public static func create(
        provider: any WalletAttestationProvider,
        instanceKey: KeyInfo,
        instanceSigner: any JwsSigner,
        clientId: String,
        rng: any Rng,
        clock: @escaping () -> Int64
    ) async throws -> WalletClientAuth {
        WalletClientAuth(
            clientId: clientId,
            attestationJwt: try await provider.walletAttestation(keyInfo: instanceKey),
            pop: ClientAttestationPop(signer: instanceSigner, clientId: clientId, rng: rng, now: clock)
        )
    }
}
