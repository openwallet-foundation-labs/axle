package com.hopae.eudi.wallet.spi

import com.hopae.eudi.wallet.cbor.cose.CoseAlgorithm
import com.hopae.eudi.wallet.cbor.cose.CoseSigner

/**
 * Bridges a [SecureArea] key into the COSE layer: `CoseSign1.sign(signer = ...)`.
 * This is the production path — private keys never leave the port.
 */
class SecureAreaCoseSigner(
    private val area: SecureArea,
    private val key: KeyHandle,
    private val signingAlgorithm: SigningAlgorithm,
    private val hint: AuthorizationHint? = null,
) : CoseSigner {

    override val algorithm: CoseAlgorithm = signingAlgorithm.coseAlgorithm

    override suspend fun sign(toBeSigned: ByteArray): ByteArray =
        area.sign(key, signingAlgorithm, toBeSigned, hint)
}
