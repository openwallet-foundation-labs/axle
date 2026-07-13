package com.hopae.eudi.wallet.trust

import com.hopae.eudi.wallet.sdjwt.Base64Url
import com.hopae.eudi.wallet.sdjwt.Jws
import com.hopae.eudi.wallet.sdjwt.JsonValue
import com.hopae.eudi.wallet.sdjwt.signingAlgorithmFromJwsName
import com.hopae.eudi.wallet.vp.RegistrationInfo
import com.hopae.eudi.wallet.vp.RegistrationLocalizedText
import com.hopae.eudi.wallet.vp.RequestTrustVerifier
import com.hopae.eudi.wallet.vp.VerifierInfo
import com.hopae.eudi.wallet.vp.VpException

/**
 * Verifies an OpenID4VP signed request object (OpenID4VP §5.10): the JWS signature against the
 * x5c leaf key, the certificate chain to a trust anchor, and the client_id scheme —
 * `x509_san_dns` (leaf SAN dNSName == client_id host) or `x509_hash`
 * (base64url(SHA-256(leaf DER)) == client_id value). The live EUDI verifier uses `x509_hash`.
 *
 * When a [wrprcVerifier] (built over the registrar CA) is supplied, a `registration_cert` carried in the
 * request's `verifier_info` is validated and bound to the WRPAC leaf; the result rides on [VerifierInfo].
 */
class X509RequestVerifier(
    private val validator: X509ChainValidator,
    private val wrprcVerifier: WRPRCVerifier? = null,
) : RequestTrustVerifier {

    override suspend fun verifyRequestObject(jws: Jws, clientId: String, scheme: String): VerifierInfo {
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

        // ETSI TS 119 475 / TS 119 472-2: verify the RP registration cert (WRPRC), when configured and
        // present. A present-but-invalid registration_cert rejects the request; an absent one leaves
        // registration null (interop with verifiers that don't yet carry a WRPRC).
        val wrprc = extractRegistrationCert(jws)
        val registration = if (wrprcVerifier != null && wrprc != null) {
            val verified = wrprcVerifier.verify(wrprc, x5c.first())
            RegistrationInfo(
                subject = verified.subject,
                entitlements = verified.entitlements,
                purpose = verified.purpose.map { RegistrationLocalizedText(it.lang, it.value) },
                intermediarySub = verified.intermediary?.sub,
                intermediaryName = verified.intermediary?.name,
                status = verified.status,
            )
        } else null

        return VerifierInfo(clientId, scheme, x5c, X509Support.commonName(leaf), trusted = true, registration = registration)
    }

    /**
     * Pulls the WRPRC (a `rc-wrp+jwt` compact JWS) out of the request object's `verifier_info` array: the
     * element whose `format` is `"registration_cert"` carries it as `base64url(serialized WRPRC)`
     * (ETSI TS 119 472-2 §6.3, REQ-RO-13/15). Returns null when no such element is present or decodable.
     */
    private fun extractRegistrationCert(jws: Jws): String? {
        val claims = JsonValue.parse(jws.payloadBytes.decodeToString()) as? JsonValue.Obj ?: return null
        val infos = (claims["verifier_info"] as? JsonValue.Arr)?.items ?: return null
        for (info in infos) {
            val obj = info as? JsonValue.Obj ?: continue
            if ((obj["format"] as? JsonValue.Str)?.value != "registration_cert") continue
            val data = (obj["data"] as? JsonValue.Str)?.value ?: continue
            return runCatching { Base64Url.decode(data).decodeToString() }.getOrNull()
        }
        return null
    }
}
