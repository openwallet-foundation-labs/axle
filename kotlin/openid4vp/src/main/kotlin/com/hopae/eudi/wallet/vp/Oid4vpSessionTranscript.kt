package com.hopae.eudi.wallet.vp

import com.hopae.eudi.wallet.cbor.Cbor
import com.hopae.eudi.wallet.cbor.CborEncoder
import com.hopae.eudi.wallet.cbor.cose.EcCurve
import com.hopae.eudi.wallet.cbor.cose.EcPublicKey
import com.hopae.eudi.wallet.sdjwt.Base64Url
import java.security.MessageDigest

/**
 * The mdoc `SessionTranscript` for OpenID4VP (OpenID4VP 1.0, "Handover and SessionTranscript
 * Definitions"): `[null, null, OpenID4VPHandover]` where
 * `OpenID4VPHandover = ["OpenID4VPHandover", SHA-256(CBOR([client_id, nonce, jwk_thumbprint, response_uri]))]`.
 * `jwk_thumbprint` is the verifier encryption key's RFC 7638 thumbprint, or null when unencrypted.
 */
object Oid4vpSessionTranscript {

    fun build(clientId: String, responseUri: String?, nonce: String, verifierJwkThumbprint: ByteArray?): Cbor {
        val handoverInfo = Cbor.Array(
            listOf(
                Cbor.Text(clientId),
                Cbor.Text(nonce),
                verifierJwkThumbprint?.let { Cbor.Bytes(it) } ?: Cbor.Null,
                Cbor.Text(responseUri ?: ""),
            )
        )
        return sessionTranscript("OpenID4VPHandover", handoverInfo)
    }

    /**
     * SessionTranscript for OpenID4VP **over the W3C Digital Credentials API** (OpenID4VP 1.0 DC API
     * profile): the handover binds the caller [origin] instead of a response_uri —
     * `OpenID4VPDCAPIHandover = ["OpenID4VPDCAPIHandover", SHA-256(CBOR([origin, nonce, jwk_thumbprint]))]`.
     */
    fun dcApi(origin: String, nonce: String, verifierJwkThumbprint: ByteArray?): Cbor {
        val handoverInfo = Cbor.Array(
            listOf(
                Cbor.Text(origin),
                Cbor.Text(nonce),
                verifierJwkThumbprint?.let { Cbor.Bytes(it) } ?: Cbor.Null,
            )
        )
        return sessionTranscript("OpenID4VPDCAPIHandover", handoverInfo)
    }

    private fun sessionTranscript(handoverType: String, handoverInfo: Cbor): Cbor {
        val hash = MessageDigest.getInstance("SHA-256").digest(CborEncoder.encode(handoverInfo))
        val handover = Cbor.Array(listOf(Cbor.Text(handoverType), Cbor.Bytes(hash)))
        return Cbor.Array(listOf(Cbor.Null, Cbor.Null, handover))
    }
}

/** RFC 7638 JWK thumbprint (SHA-256) of an EC public key — members in lexicographic order. */
fun ecJwkThumbprint(key: EcPublicKey): ByteArray {
    val crv = when (key.curve) {
        EcCurve.P256 -> "P-256"
        EcCurve.P384 -> "P-384"
        EcCurve.P521 -> "P-521"
    }
    val json = """{"crv":"$crv","kty":"EC","x":"${Base64Url.encode(key.x)}","y":"${Base64Url.encode(key.y)}"}"""
    return MessageDigest.getInstance("SHA-256").digest(json.encodeToByteArray())
}
