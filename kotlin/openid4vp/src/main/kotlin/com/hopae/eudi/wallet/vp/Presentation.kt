package com.hopae.eudi.wallet.vp

/** Everything a held credential needs to build its OpenID4VP presentation for one query. */
class PresentationContext(
    /** Concrete leaf paths DCQL selected for disclosure (SD-JWT VC claim paths / mdoc [ns, element]). */
    val disclosedPaths: List<List<String>>,
    val clientId: String,
    val nonce: String,
    val responseUri: String?,
    val issuedAt: Long,
    val transactionData: List<String>?,
    /** RFC 7638 thumbprint of the verifier's encryption key, for the mdoc OpenID4VP handover (null if unencrypted). */
    val verifierJwkThumbprint: ByteArray?,
    /** Caller web origin for a Digital Credentials API presentation; non-null selects the DC API handover. */
    val origin: String? = null,
)

/**
 * A held credential that can produce an OpenID4VP `vp_token` entry. Both SD-JWT VC
 * ([HeldSdJwtVc]) and mdoc ([HeldMdoc]) implement this so [Openid4VpClient] presents either.
 */
interface PresentableCredential : QueryableCredential {
    suspend fun present(ctx: PresentationContext): String
}
