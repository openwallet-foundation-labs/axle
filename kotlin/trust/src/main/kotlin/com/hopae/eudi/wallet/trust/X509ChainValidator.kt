package com.hopae.eudi.wallet.trust

import java.security.cert.CertPathValidator
import java.security.cert.CertificateFactory
import java.security.cert.PKIXParameters
import java.security.cert.TrustAnchor
import java.security.cert.X509Certificate
import java.util.Date

/**
 * Trust anchors (IACA / issuer-CA roots) the wallet is configured with — populated from the
 * EU LOTL / trust list by the host. Load anchors with [X509Support.parse].
 */
class TrustAnchors(val roots: List<X509Certificate>) {
    init {
        require(roots.isNotEmpty()) { "at least one trust anchor is required" }
    }

    companion object {
        fun ofDer(ders: List<ByteArray>): TrustAnchors = TrustAnchors(X509Support.parseAll(ders))
    }
}

/**
 * Validates an X.509 chain (leaf-first, excluding the anchor) to a configured [TrustAnchors]
 * via JCA PKIX. Revocation (CRL/OCSP) is off by default — enabling it makes the validator do
 * network fetches, which the host should opt into.
 */
class X509ChainValidator(
    private val anchors: TrustAnchors,
    private val checkRevocation: Boolean = false,
    private val at: () -> Date = { Date() },
) {
    private val cf = CertificateFactory.getInstance("X.509")

    /** Returns the parsed chain (leaf first) if it validates to an anchor, else throws. */
    fun validate(chainDer: List<ByteArray>): List<X509Certificate> {
        if (chainDer.isEmpty()) throw TrustException("empty certificate chain")
        val chain = X509Support.parseAll(chainDer)
        val certPath = cf.generateCertPath(chain)
        val params = PKIXParameters(anchors.roots.map { TrustAnchor(it, null) }.toSet()).apply {
            isRevocationEnabled = checkRevocation
            date = at()
        }
        try {
            CertPathValidator.getInstance("PKIX").validate(certPath, params)
        } catch (e: Exception) {
            throw TrustException("chain does not validate to a trust anchor: ${e.message}")
        }
        return chain
    }
}
