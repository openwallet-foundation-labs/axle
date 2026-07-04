package com.hopae.eudi.wallet.trust

import com.hopae.eudi.wallet.cbor.cose.EcPublicKey
import com.hopae.eudi.wallet.mdoc.MdocIssuerTrust

/**
 * Resolves an mdoc issuer key from the `issuerAuth` x5chain, validating the chain to a trust
 * anchor (the mdoc counterpart of [X5cIssuerKeyResolver]). This is how the real EUDI mdoc
 * issuer signs — a COSE x5chain leaf chaining to `PID Issuer CA`.
 */
class X5cMdocIssuerTrust(private val validator: X509ChainValidator) : MdocIssuerTrust {

    override suspend fun issuerKey(x5chain: List<ByteArray>): EcPublicKey {
        val chain = validator.validate(x5chain) // throws if not trusted
        return X509Support.ecPublicKey(chain.first())
    }
}
