package com.hopae.eudi.wallet.vp

import com.hopae.eudi.wallet.cbor.cose.CoseSigner
import com.hopae.eudi.wallet.mdoc.IssuerSigned
import com.hopae.eudi.wallet.mdoc.MdocPresenter
import com.hopae.eudi.wallet.sdjwt.Base64Url
import com.hopae.eudi.wallet.sdjwt.JsonValue
import com.hopae.eudi.wallet.spi.SigningAlgorithm

/**
 * A held mdoc (ISO 18013-5) exposed to DCQL as a [QueryableCredential] and presentable via
 * OpenID4VP. mdoc claims are a two-level tree `{ namespace: { elementIdentifier: value } }`,
 * so a DCQL claim path is `[namespace, element]` (both strings) — see [DcqlEngine] mdoc handling.
 * The [deviceSigner] holds the private key bound as the MSO `deviceKey`.
 */
class HeldMdoc(
    override val credentialId: String,
    val issuerSigned: IssuerSigned,
    private val deviceSigner: CoseSigner? = null,
    private val deviceSignAlgorithm: SigningAlgorithm = SigningAlgorithm.ES256,
) : PresentableCredential {

    override val format: String = "mso_mdoc"
    override val vct: String? = null
    override val docType: String = issuerSigned.parseMso().docType

    override val claims: JsonValue.Obj = JsonValue.Obj(
        issuerSigned.elements().map { (namespace, elements) ->
            namespace to JsonValue.Obj(elements.map { (id, value) -> id to CborJson.toJson(value) })
        }
    )

    /** Builds a base64url `DeviceResponse` disclosing the selected [namespace, element] paths. */
    override suspend fun present(ctx: PresentationContext): String {
        val signer = deviceSigner ?: throw VpException.Unsupported("mdoc presentation requires a device signer")
        val disclosed = ctx.disclosedPaths.filter { it.size >= 2 }
            .groupBy({ it[0] }, { it[1] })
        // DC API presentations bind the caller origin; the URL/QR flow binds client_id + response_uri.
        val sessionTranscript = if (ctx.origin != null) {
            Oid4vpSessionTranscript.dcApi(ctx.origin, ctx.nonce, ctx.verifierJwkThumbprint)
        } else {
            Oid4vpSessionTranscript.build(ctx.clientId, ctx.responseUri, ctx.nonce, ctx.verifierJwkThumbprint)
        }
        val deviceResponse = MdocPresenter.deviceResponse(
            issuerSigned = issuerSigned,
            docType = docType,
            disclosed = disclosed,
            sessionTranscript = sessionTranscript,
            deviceSigner = signer,
            deviceSignAlgorithm = deviceSignAlgorithm,
        )
        return Base64Url.encode(deviceResponse)
    }
}
