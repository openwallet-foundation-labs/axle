package com.hopae.eudi.wallet.cbor.cose

/** Elliptic curves used by COSE signatures in this SDK (RFC 9053 §2.1). */
enum class EcCurve(val jcaName: String, val coordinateSize: Int) {
    P256("secp256r1", 32),
    P384("secp384r1", 48),
    P521("secp521r1", 66),
}

/** Uncompressed EC public key as big-endian coordinates. */
class EcPublicKey(val curve: EcCurve, val x: ByteArray, val y: ByteArray) {
    init {
        require(x.size <= curve.coordinateSize && y.size <= curve.coordinateSize) {
            "coordinate longer than curve size"
        }
    }
}
