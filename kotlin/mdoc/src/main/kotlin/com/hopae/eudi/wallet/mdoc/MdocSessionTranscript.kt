package com.hopae.eudi.wallet.mdoc

import com.hopae.eudi.wallet.cbor.Cbor
import com.hopae.eudi.wallet.cbor.CborEncoder
import java.security.MessageDigest

/** mdoc `SessionTranscript` builders for the ISO transports (proximity handovers live in `proximity`). */
object MdocSessionTranscript {

    /**
     * SessionTranscript for the ISO `org-iso-mdoc` Digital Credentials API protocol
     * (ISO/IEC TS 18013-7:2025 Annex C): `[null, null, ["dcapi", SHA-256(CBOR([base64url(EncryptionInfo), origin]))]]`.
     */
    fun dcApiIsoMdoc(encryptionInfoBase64: String, origin: String): Cbor {
        // 18013-7 C.5: the origin binds the response to the requesting site. A blank origin cannot bind
        // anything, so the transcript must not be built from one — abort rather than emit a useless binding.
        if (origin.isBlank()) throw MdocException("DC API origin must not be blank")
        val info = Cbor.Array(listOf(Cbor.Text(encryptionInfoBase64), Cbor.Text(origin)))
        val hash = MessageDigest.getInstance("SHA-256").digest(CborEncoder.encode(info))
        val handover = Cbor.Array(listOf(Cbor.Text("dcapi"), Cbor.Bytes(hash)))
        return Cbor.Array(listOf(Cbor.Null, Cbor.Null, handover))
    }
}
