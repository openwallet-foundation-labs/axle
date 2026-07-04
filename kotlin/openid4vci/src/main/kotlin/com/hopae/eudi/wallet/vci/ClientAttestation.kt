package com.hopae.eudi.wallet.vci

import com.hopae.eudi.wallet.sdjwt.Base64Url
import com.hopae.eudi.wallet.sdjwt.JsonValue
import com.hopae.eudi.wallet.sdjwt.Jws
import com.hopae.eudi.wallet.sdjwt.JwsSigner
import com.hopae.eudi.wallet.spi.KeyInfo
import com.hopae.eudi.wallet.spi.Rng
import com.hopae.eudi.wallet.spi.SigningAlgorithm
import com.hopae.eudi.wallet.spi.WalletAttestationProvider

internal fun jwsAlgName(alg: SigningAlgorithm): String = when (alg) {
    SigningAlgorithm.ES256 -> "ES256"
    SigningAlgorithm.ES384 -> "ES384"
    SigningAlgorithm.ES512 -> "ES512"
}

/**
 * Client Attestation PoP JWT builder (OAuth 2.0 Attestation-Based Client Authentication §4.2,
 * required by HAIP). Signed by the wallet instance key bound in the attestation's `cnf`; a fresh
 * PoP per request proves possession of that key to the [audience] (the authorization server).
 */
class ClientAttestationPop(
    private val signer: JwsSigner,
    private val clientId: String,
    private val rng: Rng,
    private val now: () -> Long,
    private val lifetimeSeconds: Long = 300,
) {
    suspend fun pop(audience: String): String {
        val header = JsonValue.Obj(
            listOf(
                "typ" to JsonValue.Str("oauth-client-attestation-pop+jwt"),
                "alg" to JsonValue.Str(jwsAlgName(signer.algorithm)),
            )
        )
        val claims = JsonValue.Obj(
            listOf(
                "iss" to JsonValue.Str(clientId),
                "aud" to JsonValue.Str(audience),
                "iat" to JsonValue.NumInt(now()),
                "exp" to JsonValue.NumInt(now() + lifetimeSeconds),
                "jti" to JsonValue.Str(Base64Url.encode(rng.nextBytes(16))),
            )
        )
        return Jws.sign(header, claims.serialize().encodeToByteArray(), signer).compact()
    }
}

/**
 * Attestation-based client authentication (HAIP): pairs the wallet-provider-issued attestation JWT
 * with a per-request [ClientAttestationPop]. Attached to PAR and token requests as the
 * `OAuth-Client-Attestation` and `OAuth-Client-Attestation-PoP` headers.
 */
class WalletClientAuth(
    val clientId: String,
    val attestationJwt: String,
    private val pop: ClientAttestationPop,
) {
    suspend fun headers(audience: String): List<Pair<String, String>> = listOf(
        "OAuth-Client-Attestation" to attestationJwt,
        "OAuth-Client-Attestation-PoP" to pop.pop(audience),
    )

    companion object {
        /** Builds client auth from a [WalletAttestationProvider] and the wallet instance key. */
        suspend fun create(
            provider: WalletAttestationProvider,
            instanceKey: KeyInfo,
            instanceSigner: JwsSigner,
            clientId: String,
            rng: Rng,
            clock: () -> Long,
        ): WalletClientAuth = WalletClientAuth(
            clientId = clientId,
            attestationJwt = provider.walletAttestation(instanceKey),
            pop = ClientAttestationPop(instanceSigner, clientId, rng, clock),
        )
    }
}
