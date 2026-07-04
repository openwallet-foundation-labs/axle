package com.hopae.eudi.wallet.trust

import com.hopae.eudi.wallet.sdjwt.Jws
import com.hopae.eudi.wallet.sdjwt.JsonValue
import com.hopae.eudi.wallet.sdjwt.signingAlgorithmFromJwsName
import com.hopae.eudi.wallet.vp.RequestTrustVerifier
import com.hopae.eudi.wallet.vp.VerifierInfo
import com.hopae.eudi.wallet.vp.VpException

/**
 * Verifies an OpenID4VP signed request object (OpenID4VP §5.10): the JWS signature against the
 * x5c leaf key, the certificate chain to a trust anchor, and the client_id scheme —
 * `x509_san_dns` (leaf SAN dNSName == client_id host) or `x509_hash`
 * (base64url(SHA-256(leaf DER)) == client_id value). The live EUDI verifier uses `x509_hash`.
 */
class X509RequestVerifier(private val validator: X509ChainValidator) : RequestTrustVerifier {

    override fun verifyRequestObject(jws: Jws, clientId: String, scheme: String): VerifierInfo {
        val x5c = jws.x5c ?: throw VpException.VerifierNotTrusted("x509 request without x5c")
        val chain = validator.validate(x5c) // throws if chain is not trusted
        val leaf = chain.first()

        val alg = signingAlgorithmFromJwsName((jws.header["alg"] as? JsonValue.Str)?.value ?: "")
            ?: throw VpException.InvalidRequest("unsupported request alg")
        if (!jws.verify(X509Support.ecPublicKey(leaf), alg)) {
            throw VpException.VerifierNotTrusted("request signature invalid")
        }

        when (scheme) {
            "x509_san_dns" -> {
                val expected = clientId.substringAfter("x509_san_dns:", clientId)
                if (X509Support.dnsNames(leaf).none { it.equals(expected, ignoreCase = true) }) {
                    throw VpException.VerifierNotTrusted("client_id '$expected' not in certificate SAN dNSName")
                }
            }
            "x509_hash" -> {
                val expected = clientId.substringAfter("x509_hash:", clientId)
                if (X509Support.sha256Thumbprint(leaf) != expected) {
                    throw VpException.VerifierNotTrusted("client_id hash does not match the certificate")
                }
            }
            else -> throw VpException.Unsupported("client_id scheme '$scheme' for x509 verification")
        }

        return VerifierInfo(clientId, scheme, x5c, X509Support.commonName(leaf), trusted = true)
    }
}
