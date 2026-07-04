import CborCose
import Crypto
import Foundation
import SdJwt
import WalletAPI

func sha256(_ bytes: [UInt8]) -> [UInt8] {
    [UInt8](SHA256.hash(data: Data(bytes)))
}

func jwsAlgName(_ alg: SigningAlgorithm) -> String {
    switch alg {
    case .es256: return "ES256"
    case .es384: return "ES384"
    case .es512: return "ES512"
    }
}

/// PKCE (RFC 7636) with the S256 method — the only method HAIP permits.
public struct Pkce {
    public let codeVerifier: String
    public let codeChallenge: String
    public var method: String { "S256" }

    public static func create(rng: any Rng) -> Pkce {
        let verifier = Base64Url.encode(rng.nextBytes(32))
        let challenge = Base64Url.encode(sha256([UInt8](verifier.utf8)))
        return Pkce(codeVerifier: verifier, codeChallenge: challenge)
    }
}

/// DPoP proof builder (RFC 9449). Produces a fresh proof per request (unique jti, correct
/// htm/htu, optional ath binding to the access token, and a server nonce on retry).
public struct DpopProver {
    private let signer: any JwsSigner
    private let jwk: JsonValue
    private let rng: any Rng
    private let now: () -> Int64

    public init(signer: any JwsSigner, publicKey: EcPublicKey, rng: any Rng, now: @escaping () -> Int64) {
        self.signer = signer
        self.jwk = JwkEc.toJson(publicKey)
        self.rng = rng
        self.now = now
    }

    public func proof(method: String, url: String, accessToken: String? = nil, nonce: String? = nil) async throws -> String {
        let header = JsonValue.obj([
            ("typ", .str("dpop+jwt")),
            ("alg", .str(jwsAlgName(signer.algorithm))),
            ("jwk", jwk),
        ])
        var claims: [(String, JsonValue)] = [
            ("jti", .str(Base64Url.encode(rng.nextBytes(16)))),
            ("htm", .str(method)),
            ("htu", .str(htu(url))),
            ("iat", .numInt(now())),
        ]
        if let accessToken {
            claims.append(("ath", .str(Base64Url.encode(sha256([UInt8](accessToken.utf8))))))
        }
        if let nonce {
            claims.append(("nonce", .str(nonce)))
        }
        let jws = try await Jws.sign(header: header, payload: [UInt8](JsonValue.obj(claims).serialize().utf8), signer: signer)
        return jws.compact()
    }

    /// htu is the request URI without query and fragment (RFC 9449 §4.2).
    private func htu(_ url: String) -> String {
        var s = url
        if let q = s.firstIndex(of: "?") { s = String(s[s.startIndex..<q]) }
        if let f = s.firstIndex(of: "#") { s = String(s[s.startIndex..<f]) }
        return s
    }
}

/// OpenID4VCI key-proof-of-possession builder (§8.2.1): typ `openid4vci-proof+jwt`, the
/// holder's public JWK in the header, `aud`=issuer, and the issuer `c_nonce`.
public struct KeyProofSigner {
    private let signer: any JwsSigner
    private let jwk: JsonValue
    private let now: () -> Int64

    public init(signer: any JwsSigner, publicKey: EcPublicKey, now: @escaping () -> Int64) {
        self.signer = signer
        self.jwk = JwkEc.toJson(publicKey)
        self.now = now
    }

    public func proofJwt(credentialIssuer: String, cNonce: String?, clientId: String? = nil) async throws -> String {
        let header = JsonValue.obj([
            ("typ", .str("openid4vci-proof+jwt")),
            ("alg", .str(jwsAlgName(signer.algorithm))),
            ("jwk", jwk),
        ])
        var claims: [(String, JsonValue)] = []
        if let clientId { claims.append(("iss", .str(clientId))) }
        claims.append(("aud", .str(credentialIssuer)))
        claims.append(("iat", .numInt(now())))
        if let cNonce { claims.append(("nonce", .str(cNonce))) }
        let jws = try await Jws.sign(header: header, payload: [UInt8](JsonValue.obj(claims).serialize().utf8), signer: signer)
        return jws.compact()
    }
}
