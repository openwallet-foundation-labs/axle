package com.hopae.eudi.wallet.trust

import com.hopae.eudi.wallet.mdoc.MdocIssuerKey
import com.hopae.eudi.wallet.mdoc.MdocIssuerTrust

/**
 * Resolves an mdoc issuer key from the `issuerAuth` x5chain, validating the chain to a trust
 * anchor (the mdoc counterpart of [X5cIssuerKeyResolver]). This is how the real EUDI mdoc
 * issuer signs — a COSE x5chain leaf chaining to `PID Issuer CA`.
 */
class X5cMdocIssuerTrust(private val validator: X509ChainValidator) : MdocIssuerTrust {

    override suspend fun issuerKey(x5chain: List<ByteArray>): MdocIssuerKey {
        val chain = validator.validate(x5chain) // throws if not trusted
        val leaf = chain.first()
        // The Document Signer's own window, so MdocVerifier can apply §9.3.1 step 5 to the MSO 'signed' date.
        return MdocIssuerKey(X509Support.ecPublicKey(leaf), leaf.notBefore.toInstant(), leaf.notAfter.toInstant())
    }
}
