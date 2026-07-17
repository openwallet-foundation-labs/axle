package com.hopae.eudi.wallet.mdoc

import com.hopae.eudi.wallet.cbor.Cbor
import com.hopae.eudi.wallet.cbor.CborDecoder
import com.hopae.eudi.wallet.cbor.CborEncoder
import com.hopae.eudi.wallet.cbor.cose.CoseHeaders
import com.hopae.eudi.wallet.cbor.cose.CoseMac0
import com.hopae.eudi.wallet.cbor.cose.CoseSign1
import com.hopae.eudi.wallet.cbor.cose.CoseSigner
import com.hopae.eudi.wallet.spi.SigningAlgorithm
import com.hopae.eudi.wallet.spi.coseAlgorithm

/**
 * How the mdoc authenticates its response (ISO 18013-5 §9.1.3.5). A wallet whose `DeviceKey` is a
 * signing key produces a `deviceSignature`; one whose `DeviceKey` is a key-agreement key produces a
 * `deviceMac` instead. Readers must accept either — see [MdocReader.verifyDeviceResponse].
 */
sealed interface DeviceAuth {
    /** `deviceSignature`: an ECDSA COSE_Sign1 over `DeviceAuthentication`. */
    class Signature(
        val signer: CoseSigner,
        val algorithm: SigningAlgorithm = SigningAlgorithm.ES256,
    ) : DeviceAuth

    /**
     * `deviceMac`: HMAC-256/256 over `DeviceAuthentication` keyed by the `EMacKey` — HKDF over the ECDH
     * secret of the mdoc's `DeviceKey` and the reader's `EReaderKey`, salted by the SessionTranscript.
     * The mdoc computes that secret inside its secure area, so the MAC proves possession of `DeviceKey`
     * to *this reader only* — unlike a signature, it is not transferable to a third party.
     */
    class Mac(val emacKey: ByteArray) : DeviceAuth
}

/**
 * One document of a (possibly multi-document) `DeviceResponse`: which issuer-signed credential to
 * present, which elements to disclose, and how the device authenticates it. Each document carries
 * its own [DeviceAuth] — `DeviceAuthentication` is per-docType and each mdoc has its own DeviceKey.
 */
class PresentedDocument(
    val issuerSigned: IssuerSigned,
    val docType: String,
    /** namespace -> element identifiers to disclose. */
    val disclosed: Map<String, List<String>>,
    val deviceAuth: DeviceAuth,
    /** Device-signed data elements (namespace -> id -> value), e.g. OpenID4VP mdoc transaction data (B.2.1). */
    val deviceSignedNamespaces: Map<String, Map<String, Cbor>> = emptyMap(),
)

/**
 * Builds an mdoc `DeviceResponse` (ISO 18013-5 §8.3.2.1.2.2) for presentation: keeps only the
 * disclosed issuer-signed items and produces `DeviceSigned` — a `deviceSignature` or a `deviceMac`
 * over the `DeviceAuthentication` structure (detached payload) bound to the [sessionTranscript].
 */
object MdocPresenter {

    /** Convenience for the signature form; equivalent to passing [DeviceAuth.Signature]. */
    suspend fun deviceResponse(
        issuerSigned: IssuerSigned,
        docType: String,
        disclosed: Map<String, List<String>>,
        sessionTranscript: Cbor,
        deviceSigner: CoseSigner,
        deviceSignAlgorithm: SigningAlgorithm = SigningAlgorithm.ES256,
    ): ByteArray = deviceResponse(
        issuerSigned, docType, disclosed, sessionTranscript,
        DeviceAuth.Signature(deviceSigner, deviceSignAlgorithm),
    )

    /** Convenience for the single-document response (one `DocRequest` answered). */
    suspend fun deviceResponse(
        issuerSigned: IssuerSigned,
        docType: String,
        /** namespace -> element identifiers to disclose. */
        disclosed: Map<String, List<String>>,
        sessionTranscript: Cbor,
        deviceAuth: DeviceAuth,
        /** Device-signed data elements (namespace -> id -> value), e.g. OpenID4VP mdoc transaction data (B.2.1). */
        deviceSignedNamespaces: Map<String, Map<String, Cbor>> = emptyMap(),
    ): ByteArray = deviceResponse(
        listOf(PresentedDocument(issuerSigned, docType, disclosed, deviceAuth, deviceSignedNamespaces)),
        sessionTranscript,
    )

    /** A `DeviceResponse` answering several `DocRequest`s at once — one `Document` per [documents] entry. */
    suspend fun deviceResponse(documents: List<PresentedDocument>, sessionTranscript: Cbor): ByteArray {
        require(documents.isNotEmpty()) { "a DeviceResponse needs at least one document" }
        val deviceResponse = Cbor.CborMap(
            listOf(
                Cbor.Text("version") to Cbor.Text("1.0"),
                Cbor.Text("documents") to Cbor.Array(documents.map { document(it, sessionTranscript) }),
                Cbor.Text("status") to Cbor.int(0),
            )
        )
        return CborEncoder.encode(deviceResponse)
    }

    private suspend fun document(presented: PresentedDocument, sessionTranscript: Cbor): Cbor {
        val issuerSigned = presented.issuerSigned
        val docType = presented.docType
        val disclosed = presented.disclosed
        val deviceAuth = presented.deviceAuth
        val deviceSignedNamespaces = presented.deviceSignedNamespaces
        // Keep only the disclosed items, re-emitting their exact IssuerSignedItemBytes (#6.24).
        val filteredNs = issuerSigned.nameSpaces.mapNotNull { (ns, items) ->
            val ids = disclosed[ns] ?: return@mapNotNull null
            val kept = items.filter { it.item.elementIdentifier in ids }
            if (kept.isEmpty()) null else Cbor.Text(ns) to Cbor.Array(kept.map { CborDecoder.decode(it.itemBytes) })
        }
        val issuerSignedCbor = Cbor.CborMap(
            listOf(
                Cbor.Text("nameSpaces") to Cbor.CborMap(filteredNs),
                Cbor.Text("issuerAuth") to issuerSigned.issuerAuth.toCbor(tagged = false),
            )
        )

        // DeviceNameSpaces: empty for a basic presentation, or the provided device-signed data elements.
        val deviceNsMap = Cbor.CborMap(
            deviceSignedNamespaces.map { (ns, elements) ->
                Cbor.Text(ns) to Cbor.CborMap(elements.map { (id, value) -> Cbor.Text(id) to value })
            }
        )
        val deviceNameSpacesBytes = Cbor.Tagged(TAG_ENCODED_CBOR, Cbor.Bytes(CborEncoder.encode(deviceNsMap)))

        // DeviceAuthentication = ["DeviceAuthentication", SessionTranscript, DocType, DeviceNameSpacesBytes]
        val deviceAuthentication =
            Cbor.Array(listOf(Cbor.Text("DeviceAuthentication"), sessionTranscript, Cbor.Text(docType), deviceNameSpacesBytes))
        val deviceAuthBytes = CborEncoder.encode(Cbor.Tagged(TAG_ENCODED_CBOR, Cbor.Bytes(CborEncoder.encode(deviceAuthentication))))

        val deviceAuthEntry = when (deviceAuth) {
            is DeviceAuth.Signature -> Cbor.Text("deviceSignature") to CoseSign1.sign(
                protected = CoseHeaders.of(algorithm = deviceAuth.algorithm.coseAlgorithm),
                payload = null,
                detachedPayload = deviceAuthBytes,
                signer = deviceAuth.signer,
            ).toCbor(tagged = false)

            is DeviceAuth.Mac -> Cbor.Text("deviceMac") to CoseMac0.create(
                key = deviceAuth.emacKey,
                detachedPayload = deviceAuthBytes,
            ).toCbor(tagged = false)
        }

        val deviceSigned = Cbor.CborMap(
            listOf(
                Cbor.Text("nameSpaces") to deviceNameSpacesBytes,
                Cbor.Text("deviceAuth") to Cbor.CborMap(listOf(deviceAuthEntry)),
            )
        )

        return Cbor.CborMap(
            listOf(
                Cbor.Text("docType") to Cbor.Text(docType),
                Cbor.Text("issuerSigned") to issuerSignedCbor,
                Cbor.Text("deviceSigned") to deviceSigned,
            )
        )
    }
}
