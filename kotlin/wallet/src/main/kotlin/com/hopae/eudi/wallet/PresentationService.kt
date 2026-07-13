package com.hopae.eudi.wallet

import com.hopae.eudi.wallet.mdoc.IssuerSigned
import com.hopae.eudi.wallet.mdoc.MdocDeviceAuthMode
import com.hopae.eudi.wallet.mdoc.MdocKeyAgreement
import com.hopae.eudi.wallet.sdjwt.Base64Url
import com.hopae.eudi.wallet.sdjwt.JsonValue
import com.hopae.eudi.wallet.sdjwt.SdJwt
import com.hopae.eudi.wallet.sdjwt.SecureAreaJwsSigner
import com.hopae.eudi.wallet.spi.CredentialFormat
import com.hopae.eudi.wallet.spi.CredentialId
import com.hopae.eudi.wallet.spi.SecureArea
import com.hopae.eudi.wallet.spi.SecureAreaCoseSigner
import com.hopae.eudi.wallet.spi.SigningAlgorithm
import com.hopae.eudi.wallet.status.CredentialStatus as StatusListStatus
import com.hopae.eudi.wallet.status.StatusListClient
import com.hopae.eudi.wallet.status.StatusListException
import com.hopae.eudi.wallet.store.CredentialEnvelope
import com.hopae.eudi.wallet.store.CredentialInstance
import com.hopae.eudi.wallet.store.CredentialStore
import com.hopae.eudi.wallet.store.EnvelopeLifecycle
import com.hopae.eudi.wallet.trust.TrustException
import com.hopae.eudi.wallet.txlog.LoggedClaim
import com.hopae.eudi.wallet.txlog.LoggedDocument
import com.hopae.eudi.wallet.txlog.RelyingParty
import com.hopae.eudi.wallet.txlog.TransactionLog
import com.hopae.eudi.wallet.txlog.TransactionStatus
import com.hopae.eudi.wallet.vp.DcqlMatchResult
import com.hopae.eudi.wallet.vp.HeldMdoc
import com.hopae.eudi.wallet.vp.HeldSdJwtVc
import com.hopae.eudi.wallet.vp.Openid4VpClient
import com.hopae.eudi.wallet.vp.PresentableCredential
import com.hopae.eudi.wallet.vp.RegistrationScope
import com.hopae.eudi.wallet.vp.ResolvedRequest
import com.hopae.eudi.wallet.vp.VpErrorCode
import com.hopae.eudi.wallet.vp.VpException
import kotlinx.coroutines.CoroutineScope
import com.hopae.eudi.wallet.vp.PresentationSelection as VpSelection

/** OpenID4VP remote presentation. Bridges the store to the VP engine + records audit. */
class PresentationService internal constructor(
    private val vp: Openid4VpClient,
    private val store: CredentialStore,
    private val txlog: TransactionLog,
    private val secureAreas: List<SecureArea>,
    private val scope: CoroutineScope,
    /**
     * Registrar-scoped Token Status List client for RP registration certs (WRPRC); null when no registrar
     * anchors are configured. Used to refuse a revoked WRPRC before the consent screen.
     */
    private val registrarStatusClient: StatusListClient? = null,
    /** When true, a failed final submission is recorded with ERROR status (opt-in via config). */
    private val recordFailures: Boolean = false,
    /** ISO 18013-5 §9.1.3.5 device-auth preference for mdoc presentations (deviceMac when the verifier requests it). */
    private val deviceAuthMode: MdocDeviceAuthMode = MdocDeviceAuthMode.Signature,
    /** Host mapping for mdoc `transaction_data` device-signed elements (ISO 18013-7 B.2.1); null = reject. */
    private val transactionDataBinder: com.hopae.eudi.wallet.vp.MdocTransactionDataBinder? = null,
) {
    /** Remote (URL/QR) presentation: resolve → match stored credentials → consent → direct_post submit. */
    fun start(requestUri: String): PresentationSession = runSession(
        resolve = { catchingVp { vp.resolveRequest(requestUri) } },
        submit = { resolved, matches, selection, held ->
            PresentationState.Completed(catchingVp { vp.respond(resolved, matches, toVpSelection(selection), held) }.redirectUri)
        },
    )

    /**
     * Digital Credentials API presentation (browser-mediated). The platform hands over the [requestObject]
     * and the caller [origin]; no HTTP is performed — the response object is returned in
     * [PresentationState.Completed.dcApiResponse] for the app to pass back to the platform.
     */
    fun startDcApi(requestObject: String, origin: String): PresentationSession = runSession(
        resolve = { catchingVp { vp.resolveDcApiRequest(requestObject, origin) } },
        submit = { resolved, matches, selection, held ->
            PresentationState.Completed(
                redirectUri = null,
                dcApiResponse = catchingVp { vp.respondDcApi(resolved, matches, toVpSelection(selection), held) }.serialize(),
            )
        },
    )

    private fun runSession(
        resolve: suspend () -> ResolvedRequest,
        submit: suspend (ResolvedRequest, DcqlMatchResult, PresentationSelection, List<PresentableCredential>) -> PresentationState,
    ): PresentationSession {
        val session = PresentationSession(scope) {
            emit(PresentationState.ResolvingRequest)
            val resolved = resolve()
            // Refuse a revoked RP registration cert (WRPRC) before any matching / consent. Only runs when
            // the request actually carried a WRPRC (registration != null); absent → nothing to check.
            catchingVp { checkRegistrationStatus(resolved) }

            val envelopes = store.list().filter { it.lifecycle is EnvelopeLifecycle.Issued }
            val held = envelopes.mapNotNull { presentableFor(it, it.firstInstance()) }
            val matches = vp.match(resolved, held)
            val request = buildRequest(resolved, matches)

            when (val selection = awaitDecision(request)) {
                null -> {
                    recordDeclined(resolved)
                    // §8.5: tell the verifier the user refused so it stops waiting. Best-effort — an
                    // unreachable verifier must not turn a decline into a failure. DC API has no
                    // response_uri; there the platform surfaces the refusal (§15.9.2).
                    val redirectUri = resolved.responseUri?.let {
                        runCatching {
                            vp.reportError(resolved, VpErrorCode.ACCESS_DENIED, "the user declined to share the requested credentials")
                        }.getOrNull()?.redirectUri
                    }
                    emit(PresentationState.Declined(redirectUri))
                }
                else -> {
                    if (selection.chosen.isEmpty()) throw WalletError.Presentation.SelectionIncomplete("no credential selected")
                    emit(PresentationState.Submitting)
                    val chosenHeld = buildChosenHeld(envelopes, selection)
                    val terminal = try {
                        submit(resolved, matches, selection, chosenHeld)
                    } catch (e: Throwable) {
                        // Only the final submission failed — record the attempted disclosure with ERROR status (opt-in).
                        if (recordFailures) runCatching { recordError(resolved, selection, matches) }
                        throw e
                    }
                    recordSuccess(resolved, selection, matches)
                    emit(terminal)
                }
            }
        }
        session.launch()
        return session
    }

    private fun buildRequest(resolved: ResolvedRequest, matches: DcqlMatchResult): PresentationRequest {
        val required = matches.requiredQueryIds
        val queries = matches.candidatesByQuery.map { (queryId, candidates) ->
            QueryPresentation(
                queryId = queryId,
                required = queryId in required,
                candidates = candidates.map { PresentationCandidate(CredentialId(it.credential.credentialId), it.disclosedPaths) },
                multiple = candidates.firstOrNull()?.query?.multiple ?: false,
            )
        }
        val v = resolved.verifier
        val registration = v.registration?.let { r ->
            // RPRC_21 attribute-scope check: which requested attributes fall outside what the RP registered.
            val unregistered = RegistrationScope.unregistered(resolved.dcqlQuery, r.registeredCredentials)
            VerifierRegistration(
                subject = r.subject,
                entitlements = r.entitlements,
                purpose = r.purpose.map { PurposeText(it.lang, it.value) },
                intermediarySub = r.intermediarySub,
                intermediaryName = r.intermediaryName,
                // Reaching here means any revoked WRPRC was already refused; validated iff a status client ran.
                statusValid = if (r.status != null && registrarStatusClient != null) true else null,
                attested = r.attested,
                registryURI = r.dataset?.registryURI,
                policyURI = r.dataset?.policyURI,
                unregisteredClaims = unregistered.map { it.path },
            )
        }
        return PresentationRequest(
            verifier = VerifierInfo(v.clientId, v.clientIdScheme, v.commonName, v.trusted, registration),
            queries = queries,
            transactionData = resolved.transactionData,
            satisfiable = matches.isSatisfiable(),
            resolved = resolved,
            matches = matches,
        )
    }

    /**
     * Refuses a revoked/suspended RP registration cert (WRPRC) via the Token Status List, when the request
     * carried a WRPRC ([ResolvedRequest.verifier].registration) and a registrar status client is configured.
     * A missing WRPRC or missing status client is a no-op — interop with verifiers that don't send one yet.
     */
    private suspend fun checkRegistrationStatus(resolved: ResolvedRequest) {
        val status = resolved.verifier.registration?.status ?: return
        val client = registrarStatusClient ?: return
        val result = try {
            client.check(JsonValue.Obj(listOf("status" to status)))
        } catch (e: StatusListException) {
            throw VpException.VerifierNotTrusted("WRPRC status list check failed: ${e.message}")
        }
        if (result != StatusListStatus.VALID) {
            throw VpException.VerifierNotTrusted("WRPRC status is $result (revoked or suspended)")
        }
    }

    /** Consumes one instance per chosen credential (usage counting) and builds a signer-backed presentable. */
    private suspend fun buildChosenHeld(envelopes: List<CredentialEnvelope>, selection: PresentationSelection): List<PresentableCredential> {
        val byId = envelopes.associateBy { it.id }
        return selection.chosen.values.flatten().distinct().mapNotNull { credentialId ->
            val envelope = byId[credentialId] ?: return@mapNotNull null
            val consumed = store.consumeInstance(credentialId) ?: return@mapNotNull null
            presentableFor(envelope, consumed.instance)
        }
    }

    private fun presentableFor(envelope: CredentialEnvelope, instance: CredentialInstance?): PresentableCredential? {
        if (instance == null) return null
        val area = secureAreas.firstOrNull { it.id == instance.key.secureArea } ?: return null
        return runCatching {
            when (envelope.format) {
                is CredentialFormat.SdJwtVc -> HeldSdJwtVc(
                    envelope.id.value,
                    SdJwt.parse(instance.payload.decodeToString()),
                    SecureAreaJwsSigner(area, instance.key, SigningAlgorithm.ES256),
                )
                is CredentialFormat.MsoMdoc -> HeldMdoc(
                    envelope.id.value,
                    IssuerSigned.decode(instance.payload),
                    SecureAreaCoseSigner(area, instance.key, SigningAlgorithm.ES256),
                    deviceKeyAgreement = if (area.capabilities.keyAgreement) {
                        MdocKeyAgreement { peer -> area.keyAgreement(instance.key, peer) }
                    } else null,
                    deviceAuth = deviceAuthMode,
                    transactionDataBinder = transactionDataBinder,
                )
            }
        }.getOrNull()
    }

    private fun toVpSelection(selection: PresentationSelection): VpSelection =
        VpSelection(selection.chosen.mapValues { (_, ids) -> ids.map { it.value } })

    private fun CredentialEnvelope.firstInstance(): CredentialInstance? =
        (lifecycle as? EnvelopeLifecycle.Issued)?.instances?.firstOrNull()

    private suspend fun recordSuccess(resolved: ResolvedRequest, selection: PresentationSelection, matches: DcqlMatchResult) {
        txlog.recordPresentation(relyingPartyOf(resolved), loggedDocuments(selection, matches), TransactionStatus.SUCCESS)
    }

    private suspend fun recordDeclined(resolved: ResolvedRequest) {
        txlog.recordPresentation(relyingPartyOf(resolved), documents = emptyList(), status = TransactionStatus.INCOMPLETE)
    }

    private suspend fun recordError(resolved: ResolvedRequest, selection: PresentationSelection, matches: DcqlMatchResult) {
        txlog.recordPresentation(relyingPartyOf(resolved), loggedDocuments(selection, matches), TransactionStatus.ERROR)
    }

    private fun relyingPartyOf(resolved: ResolvedRequest): RelyingParty = RelyingParty(
        id = resolved.verifier.clientId,
        name = resolved.verifier.commonName,
        trusted = resolved.verifier.trusted,
        certificateChainDer = resolved.verifier.certificateChainDer ?: emptyList(),
    )

    private fun loggedDocuments(selection: PresentationSelection, matches: DcqlMatchResult): List<LoggedDocument> =
        selection.chosen.flatMap { (queryId, credentialIds) ->
            credentialIds.mapNotNull { credentialId ->
                val candidate = matches.candidatesByQuery[queryId].orEmpty()
                    .firstOrNull { it.credential.credentialId == credentialId.value } ?: return@mapNotNull null
                LoggedDocument(
                    format = candidate.credential.format,
                    type = candidate.credential.vct ?: candidate.credential.docType,
                    queryId = queryId,
                    claims = candidate.disclosedPaths.map { LoggedClaim(it, null) },
                )
            }
        }

    private suspend fun <T> catchingVp(block: suspend () -> T): T = try {
        block()
    } catch (e: TrustException) {
        throw WalletError.Presentation.VerifierNotTrusted(e.message ?: "reader certificate not trusted")
    } catch (e: VpException) {
        throw when (e) {
            is VpException.InvalidRequest -> WalletError.Presentation.InvalidRequest(e.message ?: "", e)
            is VpException.VerifierNotTrusted -> WalletError.Presentation.VerifierNotTrusted(e.message ?: "")
            is VpException.SelectionIncomplete -> WalletError.Presentation.SelectionIncomplete(e.message ?: "")
            is VpException.ResponseFailed -> WalletError.Presentation.ResponseRejected(e.message ?: "", e)
            is VpException.Unsupported -> WalletError.Presentation.InvalidRequest(e.message ?: "", e)
            else -> WalletError.Presentation.Unexpected(e)
        }
    }
}
