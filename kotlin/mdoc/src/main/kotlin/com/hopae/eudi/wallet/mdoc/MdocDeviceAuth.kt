package com.hopae.eudi.wallet.mdoc

import com.hopae.eudi.wallet.cbor.Cbor
import com.hopae.eudi.wallet.cbor.CborEncoder
import com.hopae.eudi.wallet.cbor.Hkdf
import com.hopae.eudi.wallet.cbor.cose.EcCurve
import com.hopae.eudi.wallet.cbor.cose.EcPublicKey
import java.security.MessageDigest

/** ISO 18013-5 §9.1.3.5 device-authentication form, chosen per credential (proximity and OpenID4VP alike). */
enum class MdocDeviceAuthMode {
    /** `deviceSignature` — an ECDSA signature any third party can verify. */
    Signature,

    /**
     * `deviceMac` — an HMAC only the reader/verifier can check, since the `EMacKey` comes from a
     * DeviceKey/EReaderKey ECDH. Non-transferable: the verifier cannot prove to anyone else that the
     * mdoc answered. Requires a key-agreement `DeviceKey` and, in OpenID4VP, an encryption-enabled request.
     */
    Mac,
}

/**
 * ECDH key agreement with the mdoc's `DeviceKey` for `deviceMac` (ISO 18013-5 §9.1.3.5). The private
 * half never leaves the secure area, so the caller supplies this bridge over its `SecureArea` port;
 * [agree] returns the raw shared secret `Zab` with the reader's/verifier's ephemeral public key.
 */
fun interface MdocKeyAgreement {
    suspend fun agree(peerPublicKey: EcPublicKey): ByteArray
}

/** `deviceMac` key derivation and the OpenID4VP algorithm-identifier mapping (shared by proximity and OID4VP). */
object MdocDeviceAuth {

    /**
     * ISO 18013-5 §9.1.3.5 `EMacKey`: HKDF-SHA256 over the ECDH secret [sharedSecret], salted by the
     * SessionTranscript, info `"EMacKey"`, 32 bytes. The salt is `SHA-256(SessionTranscriptBytes)` where
     * `SessionTranscriptBytes = #6.24(bstr .cbor SessionTranscript)` (§9.1.1.4).
     */
    fun emacKey(sharedSecret: ByteArray, sessionTranscript: Cbor): ByteArray =
        Hkdf.deriveSha256(sharedSecret, transcriptSalt(sessionTranscript), "EMacKey".encodeToByteArray(), 32)

    private fun transcriptSalt(sessionTranscript: Cbor): ByteArray {
        val stBytes = CborEncoder.encode(sessionTranscript)
        return MessageDigest.getInstance("SHA-256")
            .digest(CborEncoder.encode(Cbor.Tagged(TAG_ENCODED_CBOR, Cbor.Bytes(stBytes))))
    }

    /**
     * OpenID4VP 1.0 Appendix B.2.2 Table 2: the COSE algorithm identifier for `HMAC 256/256` with the
     * `EMacKey` established via ECDH on [curve] — what a verifier lists in `deviceauth_alg_values` to
     * request `deviceMac`. Private-use identifiers pending IANA registration.
     */
    fun macAlgForCurve(curve: EcCurve): Long = when (curve) {
        EcCurve.P256 -> -65537L
        EcCurve.P384 -> -65538L
        EcCurve.P521 -> -65539L
    }
}
