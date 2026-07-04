package com.hopae.eudi.wallet.vp

import com.hopae.eudi.wallet.sdjwt.Base64Url
import com.hopae.eudi.wallet.sdjwt.JsonValue
import com.hopae.eudi.wallet.sdjwt.JwsSigner
import com.hopae.eudi.wallet.sdjwt.SdJwt
import com.hopae.eudi.wallet.sdjwt.SdJwtHolder
import java.security.MessageDigest

/** An SD-JWT VC the wallet holds, usable as a DCQL match target and presentable over OpenID4VP. */
class HeldSdJwtVc(
    override val credentialId: String,
    val sdJwt: SdJwt,
    private val holderSigner: JwsSigner,
) : QueryableCredential {

    override val format: String = "dc+sd-jwt"
    override val claims: JsonValue.Obj = SdJwtHolder.processedClaims(sdJwt)
    override val vct: String? = (claims["vct"] as? JsonValue.Str)?.value
    override val docType: String? = null

    /**
     * Builds a presentation: selects the [disclosedPaths] disclosures and appends a KB-JWT
     * bound to [audience] (client_id) + [nonce], optionally with transaction-data hashes.
     */
    suspend fun present(
        disclosedPaths: List<List<String>>,
        audience: String,
        nonce: String,
        issuedAt: Long,
        transactionData: List<String>? = null,
    ): String {
        val pathSet = disclosedPaths.toSet()
        val extra = buildList {
            if (transactionData != null && transactionData.isNotEmpty()) {
                add("transaction_data_hashes" to JsonValue.Arr(transactionData.map { JsonValue.Str(sha256B64(it)) }))
                add("transaction_data_hashes_alg" to JsonValue.Str("sha-256"))
            }
        }
        val presented = SdJwtHolder.presentWithKeyBinding(
            issued = sdJwt,
            select = { it in pathSet },
            audience = audience,
            nonce = nonce,
            issuedAt = issuedAt,
            signer = holderSigner,
            extraClaims = extra,
        )
        return presented.serialize()
    }

    private fun sha256B64(s: String): String =
        Base64Url.encode(MessageDigest.getInstance("SHA-256").digest(s.encodeToByteArray()))
}
