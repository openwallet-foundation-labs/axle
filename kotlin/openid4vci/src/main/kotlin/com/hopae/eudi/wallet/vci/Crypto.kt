package com.hopae.eudi.wallet.vci

import com.hopae.eudi.wallet.sdjwt.Base64Url
import com.hopae.eudi.wallet.sdjwt.JsonValue
import com.hopae.eudi.wallet.sdjwt.JwkEc
import com.hopae.eudi.wallet.sdjwt.Jws
import com.hopae.eudi.wallet.sdjwt.JwsSigner
import com.hopae.eudi.wallet.spi.Rng
import java.security.MessageDigest

internal fun sha256(bytes: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(bytes)

/** PKCE (RFC 7636) with the S256 method — the only method HAIP permits. */
class Pkce private constructor(val codeVerifier: String, val codeChallenge: String) {
    val method: String get() = "S256"

    companion object {
        fun create(rng: Rng): Pkce {
            val verifier = Base64Url.encode(rng.nextBytes(32))
            val challenge = Base64Url.encode(sha256(verifier.encodeToByteArray()))
            return Pkce(verifier, challenge)
        }
    }
}

/**
 * DPoP proof builder (RFC 9449). One instance per proof-key; produces a fresh proof per
 * request (unique jti, correct htm/htu, optional ath binding to the access token, and a
 * server-provided nonce on retry).
 */
class DpopProver(
    private val signer: JwsSigner,
    publicKey: com.hopae.eudi.wallet.cbor.cose.EcPublicKey,
    private val rng: Rng,
    private val now: () -> Long,
) {
    private val jwk: JsonValue.Obj = JwkEc.toJson(publicKey)

    suspend fun proof(
        method: String,
        url: String,
        accessToken: String? = null,
        nonce: String? = null,
    ): String {
        val header = JsonValue.Obj(
            listOf(
                "typ" to JsonValue.Str("dpop+jwt"),
                "alg" to JsonValue.Str(jwsAlg()),
                "jwk" to jwk,
            )
        )
        val claims = mutableListOf<Pair<String, JsonValue>>(
            "jti" to JsonValue.Str(Base64Url.encode(rng.nextBytes(16))),
            "htm" to JsonValue.Str(method),
            "htu" to JsonValue.Str(htu(url)),
            "iat" to JsonValue.NumInt(now()),
        )
        accessToken?.let { claims.add("ath" to JsonValue.Str(Base64Url.encode(sha256(it.encodeToByteArray())))) }
        nonce?.let { claims.add("nonce" to JsonValue.Str(it)) }
        return Jws.sign(header, JsonValue.Obj(claims).serialize().encodeToByteArray(), signer).compact()
    }

    private fun jwsAlg(): String = when (signer.algorithm) {
        com.hopae.eudi.wallet.spi.SigningAlgorithm.ES256 -> "ES256"
        com.hopae.eudi.wallet.spi.SigningAlgorithm.ES384 -> "ES384"
        com.hopae.eudi.wallet.spi.SigningAlgorithm.ES512 -> "ES512"
    }

    /** htu is the request URI without query and fragment (RFC 9449 §4.2). */
    private fun htu(url: String): String = url.substringBefore('?').substringBefore('#')
}

/**
 * OpenID4VCI key-proof-of-possession builder (§8.2.1): typ `openid4vci-proof+jwt`, the
 * holder's public JWK in the header, `aud`=issuer, and the issuer `c_nonce`.
 */
class KeyProofSigner(
    private val signer: JwsSigner,
    publicKey: com.hopae.eudi.wallet.cbor.cose.EcPublicKey,
    private val now: () -> Long,
) {
    private val jwk: JsonValue.Obj = JwkEc.toJson(publicKey)

    suspend fun proofJwt(credentialIssuer: String, cNonce: String?, clientId: String? = null): String {
        val header = JsonValue.Obj(
            listOf(
                "typ" to JsonValue.Str("openid4vci-proof+jwt"),
                "alg" to JsonValue.Str(
                    when (signer.algorithm) {
                        com.hopae.eudi.wallet.spi.SigningAlgorithm.ES256 -> "ES256"
                        com.hopae.eudi.wallet.spi.SigningAlgorithm.ES384 -> "ES384"
                        com.hopae.eudi.wallet.spi.SigningAlgorithm.ES512 -> "ES512"
                    }
                ),
                "jwk" to jwk,
            )
        )
        val claims = mutableListOf<Pair<String, JsonValue>>(
            "aud" to JsonValue.Str(credentialIssuer),
            "iat" to JsonValue.NumInt(now()),
        )
        clientId?.let { claims.add(0, "iss" to JsonValue.Str(it)) }
        cNonce?.let { claims.add("nonce" to JsonValue.Str(it)) }
        return Jws.sign(header, JsonValue.Obj(claims).serialize().encodeToByteArray(), signer).compact()
    }
}
