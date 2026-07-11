@file:OptIn(androidx.credentials.ExperimentalDigitalCredentialApi::class)

package com.hopae.eudi.demo

import android.content.Intent
import android.os.Bundle
import android.util.Base64
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.credentials.GetDigitalCredentialOption
import androidx.credentials.provider.PendingIntentHandler
import androidx.lifecycle.lifecycleScope
import com.hopae.eudi.wallet.PresentationSelection
import com.hopae.eudi.wallet.PresentationState
import com.hopae.eudi.wallet.android.dcapi.DcApiRequest
import com.hopae.eudi.wallet.android.dcapi.DcApiResult
import com.hopae.eudi.wallet.mdoc.DeviceRequest
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch

/**
 * Handles a Digital Credentials API (OpenID4VP / org-iso-mdoc) request routed to this wallet by the
 * Credential Manager. The UI-less plumbing — envelope parsing, origin, and result marshalling — lives in the
 * `com.hopae.eudi.android:dcapi` library (`DcApiRequest` / `DcApiResult`); this Activity owns the flow: show
 * the app's consent, drive the SDK, return the response.
 */
class GetCredentialActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val wallet = DemoWallet.get(this)
        val resultData = Intent()

        val request = PendingIntentHandler.retrieveProviderGetCredentialRequest(intent)
        val option = request?.credentialOptions?.filterIsInstance<GetDigitalCredentialOption>()?.firstOrNull()
        if (request == null || option == null) { finishError(resultData, "no digital credential request"); return }

        val origin = DcApiRequest.originOf(request, allowlist())
        LogStore.log("DC API request · origin=$origin · protocols=${DcApiRequest.protocolsOffered(option.requestJson)}")

        // org-iso-mdoc (ISO 18013-7): raw mdoc DeviceRequest → HPKE-encrypted DeviceResponse.
        val mdoc = DcApiRequest.matchProtocol(option.requestJson, listOf("org-iso-mdoc", "org.iso.mdoc"))
        if (mdoc != null) {
            val (proto, data) = mdoc
            val items = runCatching {
                DeviceRequest.decode(Base64.decode(data.getString("deviceRequest"), Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP)).docRequests.map { dr ->
                    ConsentItem(dr.docType, dr.requested.flatMap { (_, els) -> els.map { it.identifier } })
                }
            }.getOrDefault(emptyList())
            showConsent(origin, trusted = false, items,
                onApprove = {
                    lifecycleScope.launch {
                        runCatching {
                            val response = wallet.proximity.respondDcApiMdoc(data.getString("deviceRequest"), data.getString("encryptionInfo"), origin)
                            DcApiResult.setResponse(resultData, DcApiResult.mdocResponseJson(proto, response))
                            LogStore.log("✅ DC API (mdoc) response returned to caller")
                            setResult(RESULT_OK, resultData)
                        }.onFailure { finishExceptionData(resultData, it.message) }
                        finish()
                    }
                },
                onDecline = { finishError(resultData, "declined by user") })
            return
        }

        val openid4vp = DcApiRequest.extractOpenId4Vp(option.requestJson)
        if (openid4vp == null) { finishError(resultData, "no openid4vp request"); return }

        lifecycleScope.launch {
            runCatching {
                val session = wallet.presentation.startDcApi(openid4vp, origin)
                val resolved = session.state.first { it is PresentationState.RequestResolved || it is PresentationState.Failed }
                if (resolved is PresentationState.Failed) throw resolved.error
                val presentation = (resolved as PresentationState.RequestResolved).request
                LogStore.log("DC API verifier=${presentation.verifier.clientId} · satisfiable=${presentation.satisfiable}")
                val items = presentation.queries.map { q ->
                    ConsentItem(q.queryId, q.candidates.firstOrNull()?.disclosedPaths?.map { it.joinToString(" › ") } ?: listOf("no matching credential"))
                }
                showConsent(presentation.verifier.commonName ?: presentation.verifier.clientId, presentation.verifier.trusted, items,
                    onApprove = {
                        lifecycleScope.launch {
                            runCatching {
                                session.respond(PresentationSelection.auto(presentation))
                                when (val done = session.state.first { it.isTerminal }) {
                                    is PresentationState.Completed -> {
                                        DcApiResult.setResponse(resultData, done.dcApiResponse ?: error("no DC API response produced"))
                                        LogStore.log("✅ DC API response returned to caller")
                                        setResult(RESULT_OK, resultData)
                                    }
                                    is PresentationState.Failed -> throw done.error
                                    else -> error("unexpected terminal state $done")
                                }
                            }.onFailure { finishExceptionData(resultData, it.message) }
                            finish()
                        }
                    },
                    onDecline = { finishError(resultData, "declined by user") })
            }.onFailure { finishError(resultData, it.message) }
        }
    }

    private fun showConsent(verifier: String, trusted: Boolean, items: List<ConsentItem>, onApprove: () -> Unit, onDecline: () -> Unit) {
        setContent { DcApiConsentScreen(verifier, trusted, items, onApprove, onDecline) }
    }

    /** The app-owned privileged-caller allowlist (which browsers may present a web origin). */
    private fun allowlist(): String = runCatching {
        assets.open("privileged_allowlist.json").bufferedReader().use { it.readText() }
    }.getOrDefault("""{"apps":[]}""")

    private fun finishError(resultData: Intent, message: String?) { finishExceptionData(resultData, message); finish() }

    private fun finishExceptionData(resultData: Intent, message: String?) {
        LogStore.log("❌ DC API: ${message ?: "error"}")
        DcApiResult.setError(resultData, message)
        setResult(RESULT_OK, resultData)
    }
}
