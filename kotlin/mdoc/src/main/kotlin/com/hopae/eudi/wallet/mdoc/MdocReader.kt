package com.hopae.eudi.wallet.mdoc

import com.hopae.eudi.wallet.cbor.Cbor
import com.hopae.eudi.wallet.cbor.CborEncoder
import com.hopae.eudi.wallet.cbor.cose.CoseHeaders
import com.hopae.eudi.wallet.cbor.cose.CoseSign1
import com.hopae.eudi.wallet.cbor.cose.CoseSigner
import com.hopae.eudi.wallet.cbor.cose.EcPublicKey
import com.hopae.eudi.wallet.spi.SigningAlgorithm
import com.hopae.eudi.wallet.spi.coseAlgorithm
import java.time.Instant

/**
 * A document (and its elements) the reader wants from a wallet.
 *
 * [intentToRetain] is the default flag for every requested element; [retainedElements] overrides it per element
 * (namespace -> identifiers), which is the granularity ISO 18013-5 §8.3.2.1.2.1 actually defines — the CDDL is
 * `DataElementIdentifier => IntentToRetain`, so a reader that keeps the customer's name but only glances at
 * their photo has to say so element by element.
 */
class RequestedDocument(
    val docType: String,
    val elements: Map<String, List<String>>,
    val intentToRetain: Boolean = false,
    val retainedElements: Map<String, Set<String>> = emptyMap(),
) {
    /** The `IntentToRetain` value to emit for [elementId] in [namespace]. */
    internal fun retains(namespace: String, elementId: String): Boolean =
        retainedElements[namespace]?.contains(elementId) ?: intentToRetain
}

/** Reader authentication material: signs `readerAuth` and presents the reader certificate chain. */
class ReaderAuthSigner(val signer: CoseSigner, val x5chain: List<ByteArray>, val algorithm: SigningAlgorithm = SigningAlgorithm.ES256)

/** A reader-verified document: integrity- and holder-authenticated disclosed elements. */
class VerifiedDocument(
    val docType: String,
    val elements: Map<String, Map<String, Cbor>>,
    /** True once the `deviceSignature` bound to this SessionTranscript verified (holder binding). */
    val deviceAuthenticated: Boolean,
    /**
     * Why verification did not complete, when [deviceAuthenticated] is false — e.g. `"digest mismatch for
     * org.iso.18013.5.1/portrait"`, `"issuerAuth signature invalid"`, `"mdoc expired (validUntil=…)"`. Null
     * when the document verified, or when the reader was configured without an issuer trust and never tried.
     *
     * "Untrusted issuer" and "forged response" are not the same finding: a caller that treats every
     * unverified document alike cannot tell a missing trust anchor from a tampered digest, so the reason
     * travels with the document rather than being swallowed where verification failed.
     */
    val verificationError: String? = null,
)

/**
 * The verifier/reader side of mdoc (ISO 18013-5): builds `DeviceRequest`s (optionally signing
 * `readerAuth`) and verifies `DeviceResponse`s — issuer trust + digest integrity **and** the
 * `deviceSignature` holder binding over the SessionTranscript. The wallet side is [MdocPresenter]
 * / [MdocVerifier]; this is its symmetric counterpart for a reader/verifier app.
 */
class MdocReader(
    private val readerAuth: ReaderAuthSigner? = null,
    private val issuerTrust: MdocIssuerTrust? = null,
    private val now: () -> Instant = { Instant.now() },
) {
    suspend fun buildDeviceRequest(documents: List<RequestedDocument>, sessionTranscript: Cbor): ByteArray {
        val docRequests = documents.map { doc ->
            // ISO 18013-5 §7.2.5: "an mDL reader shall not request more than two age_over_NN data elements".
            // Scoped per document — the clause governs a data model's own age attestations, and a request for
            // several doctypes that each carry one is not the ladder (16/18/21/25) the cap exists to stop.
            val ageElements = doc.elements.values.sumOf { AgeAttestation.requestedCount(it) }
            require(ageElements <= AgeAttestation.MAX_REQUESTED) {
                "ISO 18013-5 §7.2.5 allows at most ${AgeAttestation.MAX_REQUESTED} age_over_NN elements per " +
                    "request; ${doc.docType} asks for $ageElements"
            }
            val nameSpaces = Cbor.CborMap(doc.elements.map { (ns, elems) ->
                Cbor.Text(ns) to Cbor.CborMap(elems.map { Cbor.Text(it) to Cbor.Bool(doc.retains(ns, it)) })
            })
            val itemsRequest = Cbor.CborMap(listOf(Cbor.Text("docType") to Cbor.Text(doc.docType), Cbor.Text("nameSpaces") to nameSpaces))
            val itemsRequestBytes = Cbor.Tagged(TAG_ENCODED_CBOR, Cbor.Bytes(CborEncoder.encode(itemsRequest)))

            val entries = mutableListOf<Pair<Cbor, Cbor>>(Cbor.Text("itemsRequest") to itemsRequestBytes)
            readerAuth?.let { ra ->
                val readerAuthentication = Cbor.Array(listOf(Cbor.Text("ReaderAuthentication"), sessionTranscript, itemsRequestBytes))
                val readerAuthBytes = CborEncoder.encode(Cbor.Tagged(TAG_ENCODED_CBOR, Cbor.Bytes(CborEncoder.encode(readerAuthentication))))
                val sig = CoseSign1.sign(
                    protected = CoseHeaders.of(algorithm = ra.algorithm.coseAlgorithm),
                    unprotected = CoseHeaders(Cbor.CborMap(listOf(Cbor.int(33) to Cbor.Array(ra.x5chain.map { Cbor.Bytes(it) })))),
                    payload = null, detachedPayload = readerAuthBytes, signer = ra.signer,
                )
                entries.add(Cbor.Text("readerAuth") to sig.toCbor(tagged = false))
            }
            Cbor.CborMap(entries)
        }
        val deviceRequest = Cbor.CborMap(
            listOf(Cbor.Text("version") to Cbor.Text("1.0"), Cbor.Text("docRequests") to Cbor.Array(docRequests))
        )
        return CborEncoder.encode(deviceRequest)
    }

    /**
     * Verifies each document in a `DeviceResponse`: the issuer signature + digests + validity
     * (via [MdocVerifier]) and the `deviceSignature` over `DeviceAuthentication` bound to
     * [sessionTranscript] (proving the response came from the credential's holder, this session).
     */
    suspend fun verifyDeviceResponse(
        deviceResponse: ByteArray,
        sessionTranscript: Cbor,
        /**
         * Derives the ISO 18013-5 §9.1.3.5 `EMacKey` from the mdoc `DeviceKey` (ECDH with the reader's
         * EReaderKey, then HKDF over the SessionTranscript). Required to verify `deviceMac`; if absent,
         * a MAC-authenticated document fails verification.
         */
        emacKey: (suspend (EcPublicKey) -> ByteArray)? = null,
    ): List<VerifiedDocument> {
        val response = DeviceResponse.decode(deviceResponse)
        // §8.3.2.1.2.3 Table 8: a non-zero status means the mdoc returned no documents, with a reason
        // (10 general / 11 CBOR-decode / 12 CBOR-validation). Surface it rather than reporting an empty list.
        if (response.status != 0L) throw MdocException("mdoc returned DeviceResponse status ${response.status}")
        val trust = issuerTrust ?: throw MdocException("verifyDeviceResponse requires an issuer trust")
        val verifier = MdocVerifier(trust, now)
        return response.documents.map { doc ->
            val verified = verifier.verify(doc.issuerSigned) // issuerAuth + digests + validity
            // §9.3.1 step 4: "verify that the DocType in the MSO matches the relevant DocType in the Documents
            // structure". DeviceAuthentication is signed over the *Document's* docType while the elements are
            // vouched for by the *MSO's*; if they disagree, the two halves describe different credentials.
            if (verified.docType != doc.docType) {
                throw MdocException("docType mismatch: MSO says '${verified.docType}', Document says '${doc.docType}'")
            }
            val deviceAuthentication = Cbor.Array(listOf(Cbor.Text("DeviceAuthentication"), sessionTranscript, Cbor.Text(doc.docType), doc.deviceNameSpacesBytes))
            val deviceAuthBytes = CborEncoder.encode(Cbor.Tagged(TAG_ENCODED_CBOR, Cbor.Bytes(CborEncoder.encode(deviceAuthentication))))
            val bound = when {
                doc.deviceSignature != null -> doc.deviceSignature.verify(verified.deviceKey, detachedPayload = deviceAuthBytes)
                doc.deviceMac != null -> {
                    val key = emacKey?.invoke(verified.deviceKey)
                        ?: throw MdocException("deviceMac verification requires the reader ephemeral key (emacKey)")
                    doc.deviceMac.verify(key, detachedPayload = deviceAuthBytes)
                }
                else -> throw MdocException("no device authentication for ${doc.docType}")
            }
            if (!bound) throw MdocException("device authentication invalid — holder binding failed for ${doc.docType}")
            VerifiedDocument(verified.docType, verified.elements, deviceAuthenticated = true)
        }
    }
}
