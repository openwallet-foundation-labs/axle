package com.hopae.eudi.wallet.trust

import com.hopae.eudi.wallet.cbor.cose.EcPublicKey
import com.hopae.eudi.wallet.mdoc.MdocReaderTrust

/**
 * Resolves an mdoc reader's key from the `readerAuth` x5chain, validating the chain to a **reader**
 * trust anchor (configure [validator] with the reader-CA anchors, distinct from issuer anchors).
 * This authenticates the verifier that is asking for data (ISO 18013-5 §9.1.4).
 */
class X5cMdocReaderTrust(private val validator: X509ChainValidator) : MdocReaderTrust {

    override suspend fun readerKey(x5chain: List<ByteArray>): EcPublicKey {
        val chain = validator.validate(x5chain) // throws if not trusted
        return X509Support.ecPublicKey(chain.first())
    }
}
