package com.hopae.eudi.wallet.mdoc

import com.hopae.eudi.wallet.cbor.Cbor
import com.hopae.eudi.wallet.cbor.CborDecoder
import com.hopae.eudi.wallet.cbor.cose.CoseMac0
import com.hopae.eudi.wallet.cbor.cose.CoseSign1

/** One document inside a `DeviceResponse` (ISO 18013-5 §8.3.2.1.2.2), reader-side view. */
class ResponseDocument(
    val docType: String,
    val issuerSigned: IssuerSigned,
    /** `DeviceNameSpacesBytes` (#6.24) as received — for `DeviceAuthentication` reconstruction. */
    val deviceNameSpacesBytes: Cbor,
    /** COSE_Sign1 device authentication, or null when the document uses [deviceMac] instead. */
    val deviceSignature: CoseSign1?,
    /** COSE_Mac0 device authentication (ISO 18013-5 §9.1.3.5), for key-agreement device keys. */
    val deviceMac: CoseMac0? = null,
)

/** A wallet's `DeviceResponse` as parsed by the reader/verifier. */
class DeviceResponse(val version: String, val status: Long, val documents: List<ResponseDocument>) {

    companion object {
        fun decode(bytes: ByteArray): DeviceResponse {
            val map = CborDecoder.decode(bytes) as? Cbor.CborMap ?: throw MdocException("DeviceResponse must be a map")
            val version = (map.field("version") as? Cbor.Text)?.value ?: throw MdocException("missing version")
            val status = (map.field("status") as? Cbor.UInt)?.value?.toLong() ?: 0L
            val documents = (map.field("documents") as? Cbor.Array)?.items?.map { doc ->
                val docMap = doc as? Cbor.CborMap ?: throw MdocException("document must be a map")
                val docType = (docMap.field("docType") as? Cbor.Text)?.value ?: throw MdocException("missing docType")
                val issuerSigned = IssuerSigned.fromCbor(docMap.field("issuerSigned") ?: throw MdocException("missing issuerSigned"))
                val deviceSigned = docMap.field("deviceSigned") as? Cbor.CborMap ?: throw MdocException("missing deviceSigned")
                val deviceNameSpacesBytes = deviceSigned.field("nameSpaces") ?: throw MdocException("missing deviceSigned nameSpaces")
                val deviceAuth = deviceSigned.field("deviceAuth") as? Cbor.CborMap ?: throw MdocException("missing deviceAuth")
                val deviceSignature = deviceAuth.field("deviceSignature")?.let { CoseSign1.fromCbor(it) }
                val deviceMac = deviceAuth.field("deviceMac")?.let { CoseMac0.fromCbor(it) }
                if (deviceSignature == null && deviceMac == null) throw MdocException("deviceAuth has neither deviceSignature nor deviceMac")
                ResponseDocument(docType, issuerSigned, deviceNameSpacesBytes, deviceSignature, deviceMac)
            } ?: emptyList()
            return DeviceResponse(version, status, documents)
        }

        private fun Cbor.CborMap.field(name: String): Cbor? =
            entries.firstOrNull { (k, _) -> (k as? Cbor.Text)?.value == name }?.second
    }
}
