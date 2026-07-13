package com.hopae.eudi.wallet

import com.hopae.eudi.wallet.status.StatusListClient
import com.hopae.eudi.wallet.store.CredentialStore
import com.hopae.eudi.wallet.trust.TrustAnchorSource
import com.hopae.eudi.wallet.trust.TrustAnchors
import com.hopae.eudi.wallet.trust.X509ChainValidator
import com.hopae.eudi.wallet.trust.WRPRCVerifier
import com.hopae.eudi.wallet.trust.X509RequestVerifier
import com.hopae.eudi.wallet.trust.X5cIssuerKeyResolver
import com.hopae.eudi.wallet.trust.X5cMdocIssuerTrust
import com.hopae.eudi.wallet.trust.X5cMdocReaderTrust
import com.hopae.eudi.wallet.sdjwt.Base64Url
import com.hopae.eudi.wallet.sdjwt.JwtTimeValidator
import com.hopae.eudi.wallet.txlog.TransactionLog
import com.hopae.eudi.wallet.vci.Openid4VciClient
import com.hopae.eudi.wallet.vp.Openid4VpClient
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel

/**
 * The unified EUDI Wallet SDK facade. Multi-instance, thread-safe; no global
 * state. [close] cancels in-flight sessions and is idempotent.
 *
 * Phases A–C wire credential storage, DCQL retrieval, status, issuance, and remote presentation; proximity follows.
 */
class Wallet private constructor(
    val credentials: CredentialsService,
    val issuance: IssuanceService,
    val presentation: PresentationService,
    val proximity: ProximityService,
    /** The reader/verifier side of ISO 18013-5 proximity (request + verify documents from another wallet). */
    val reader: ProximityReaderService,
    /** Audit history of presentations/issuances (ARF/GDPR) — query with [TransactionLog.history]/[TransactionLog.query]. */
    val transactions: TransactionLog,
    private val scope: CoroutineScope,
) : AutoCloseable {

    @Volatile
    private var closed = false

    override fun close() {
        if (closed) return
        closed = true
        scope.cancel()
    }

    companion object {
        fun create(config: WalletConfig, ports: WalletPorts): Wallet {
            val clockSeconds: () -> Long = { ports.clock.now().epochSecond }
            val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
            val store = CredentialStore(ports.storage)

            // Lazy issuer anchors: only required when a status token is actually verified.
            val issuerAnchors = TrustAnchorSource {
                require(config.trust.issuerAnchorsDer.isNotEmpty()) { "no issuer trust anchors configured for status verification" }
                TrustAnchors.ofDer(config.trust.issuerAnchorsDer)
            }
            val issuerValidator = X509ChainValidator(issuerAnchors, at = { java.util.Date.from(ports.clock.now()) })
            val statusClient = StatusListClient(ports.http, X5cIssuerKeyResolver(issuerValidator), clockSeconds)

            val txlog = TransactionLog(
                store = ports.transactionLogStore,
                idGenerator = { "txn-" + Base64Url.encode(ports.rng.nextBytes(12)) },
                clock = clockSeconds,
            )
            // HAIP attestation-based client auth: enabled when a Wallet Provider is wired (else plain client_id).
            val clientAuth = ports.walletAttestation?.let {
                AttestationClientAuth(config.issuance.clientId, it, ports.defaultSecureArea, ports.storage, ports.rng, clockSeconds)
            }
            val vci = Openid4VciClient(ports.http, ports.rng, clockSeconds, config.issuance.clientId, clientAuth = clientAuth)
            val issuance = IssuanceService(vci, store, ports.storage, ports.defaultSecureArea, scope, ports.rng, ports.clock, config.issuance.redirectUri, txlog)

            // Reader trust: one validator over the configured reader anchors, shared by remote (signed OpenID4VP
            // request objects) and proximity (mdoc reader authentication). No anchors → readers stay untrusted.
            val readerValidator = config.trust.readerAnchorsDer.takeIf { it.isNotEmpty() }?.let { anchors ->
                X509ChainValidator(TrustAnchorSource { TrustAnchors.ofDer(anchors) }, at = { java.util.Date.from(ports.clock.now()) })
            }

            // Registrar trust: the RP registration cert (WRPRC) and its status list chain to the registrar CA.
            // When configured, the request verifier validates a WRPRC carried in `verifier_info` and binds it to
            // the reader's WRPAC; the registrar-scoped status client lets the wallet refuse a revoked WRPRC.
            val registrarValidator = config.trust.registrarAnchorsDer.takeIf { it.isNotEmpty() }?.let { anchors ->
                X509ChainValidator(TrustAnchorSource { TrustAnchors.ofDer(anchors) }, at = { java.util.Date.from(ports.clock.now()) })
            }
            val wrprcVerifier = registrarValidator?.let { WRPRCVerifier(it, JwtTimeValidator(now = { ports.clock.now() })) }
            val registrarStatusClient = registrarValidator?.let { StatusListClient(ports.http, X5cIssuerKeyResolver(it), clockSeconds) }

            val vp = Openid4VpClient(ports.http, clockSeconds, readerValidator?.let { X509RequestVerifier(it, wrprcVerifier) }, ports.rng)
            val recordFailures = config.transactionLog.recordFailures
            val presentation = PresentationService(vp, store, txlog, ports.secureAreas, scope, registrarStatusClient, recordFailures, config.presentation.mdocDeviceAuth, config.presentation.mdocTransactionDataBinder)
            val proximity = ProximityService(store, txlog, ports.secureAreas, scope, readerValidator?.let { X5cMdocReaderTrust(it) }, recordFailures, config.presentation.mdocDeviceAuth, config.presentation.proximitySessionCurve)
            // Reader side: verify presented mdocs against the same issuer anchors used for status/issuance.
            val reader = ProximityReaderService(X5cMdocIssuerTrust(issuerValidator))

            return Wallet(
                credentials = CredentialsService(store, statusClient),
                issuance = issuance,
                presentation = presentation,
                proximity = proximity,
                reader = reader,
                transactions = txlog,
                scope = scope,
            )
        }
    }
}
