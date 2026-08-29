package com.hopae.eudi.wallet

import com.hopae.eudi.wallet.cbor.Cbor
import com.hopae.eudi.wallet.mdoc.DeviceRequest
import com.hopae.eudi.wallet.proximity.SessionEncryption
import com.hopae.eudi.wallet.spi.CredentialId

/**
 * What an in-person reader asked for (ISO 18013-5 device retrieval), ready for the consent screen: the
 * requested documents/elements and which stored credential answers each. Raw request + session carried for the reply.
 */
class ProximityRequest internal constructor(
    val documents: List<RequestedDocumentView>,
    val satisfiable: Boolean,
    /** Who is asking — from verified reader authentication (ISO 18013-5 §9.1.4), if present and trusted. */
    val reader: ProximityReaderInfo,
    internal val deviceRequest: DeviceRequest,
    internal val transcript: Cbor,
    internal val session: SessionEncryption,
)

/**
 * The in-person reader's identity. [trusted] is true only when the request was reader-authenticated
 * and the reader certificate chained to a configured reader anchor (config.trust.readerAnchorsDer).
 */
class ProximityReaderInfo(
    val trusted: Boolean,
    val commonName: String?,
    val certificateChainDer: List<ByteArray>,
)

/** One requested document: the doctype, the elements the reader wants, and the matching stored credential. */
class RequestedDocumentView(
    val docType: String,
    val requestedElements: Map<String, List<String>>,
    /** Stored credentials that can answer this doctype; the holder chooses one when there is more than one. */
    val candidates: List<CredentialId>,
    /**
     * The subset of [requestedElements] the reader flagged `IntentToRetain` (ISO 18013-5 §8.3.2.1.2.1):
     * namespace -> element identifiers it intends to keep beyond the transaction. Everything else the reader
     * "shall not retain … including digests and signatures".
     *
     * The flag is per data element in the CDDL and it is the only thing distinguishing a look-at-me check from
     * a record the verifier files away, so it belongs on the consent screen next to the element it qualifies
     * (Annex E: "Consent applies to both selective disclosure and authorization for intent-to-retain").
     */
    val retainedElements: Map<String, List<String>> = emptyMap(),
)

/**
 * An org-iso-mdoc (ISO 18013-7) Digital Credentials API request, resolved for the consent screen: the requested
 * documents/elements + matching credentials, and the verified reader identity. Unlike the proximity flow there is
 * no BLE session — the response is produced separately (on approval) via [ProximityService.respondDcApiMdoc].
 */
class DcApiMdocRequest internal constructor(
    val documents: List<RequestedDocumentView>,
    val satisfiable: Boolean,
    /** Who is asking — from verified reader authentication (ISO 18013-5 §9.1.4), if present and trusted. */
    val reader: ProximityReaderInfo,
)

/** The user's choice of which stored credential answers each requested doctype. */
class ProximitySelection(val chosen: Map<String, CredentialId>) {
    companion object {
        fun auto(request: ProximityRequest): ProximitySelection = preferring(request.documents, emptyList())

        /**
         * [auto], except that a choice the User has already made wins over "the first candidate" — see
         * [PresentationSelection.preferring]. Takes the documents rather than a request so it serves both the
         * proximity flow ([ProximityRequest]) and the `org-iso-mdoc` DC API flow ([DcApiMdocRequest]), where
         * the OS selector has already resolved the pick before the wallet is started.
         */
        fun preferring(documents: List<RequestedDocumentView>, preferred: Collection<CredentialId>): ProximitySelection =
            ProximitySelection(
                documents.mapNotNull { doc ->
                    val pick = doc.candidates.firstOrNull { it in preferred } ?: doc.candidates.firstOrNull()
                    pick?.let { doc.docType to it }
                }.toMap(),
            )
    }
}

/** Proximity presentation session state. */
sealed interface ProximityState {
    data object GeneratingEngagement : ProximityState

    /**
     * Engagement is ready and the wallet is waiting for the reader. [deviceEngagement] is rendered as a QR
     * code (`mdoc:` + base64url); [handoverNdef], when non-null, is the NFC Handover Select message the app
     * should serve over HCE (NFC static handover) instead of / alongside the QR.
     */
    data class EngagementReady(val deviceEngagement: ByteArray, val handoverNdef: ByteArray? = null) : ProximityState
    data class RequestReceived(val request: ProximityRequest) : ProximityState
    data object Submitting : ProximityState
    data object Completed : ProximityState
    data object Declined : ProximityState
    data class Failed(val error: WalletError.Proximity) : ProximityState

    val isTerminal: Boolean get() = this is Completed || this is Declined || this is Failed
}
