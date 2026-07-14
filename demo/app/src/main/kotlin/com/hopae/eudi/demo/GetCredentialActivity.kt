@file:OptIn(androidx.credentials.ExperimentalDigitalCredentialApi::class)

package com.hopae.eudi.demo

import android.content.Intent
import android.os.Bundle
import android.util.Base64
import androidx.activity.compose.setContent
import androidx.credentials.GetDigitalCredentialOption
import androidx.credentials.provider.PendingIntentHandler
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.lifecycleScope
import com.hopae.eudi.demo.ui.theme.WalletTheme
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
class GetCredentialActivity : FragmentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val resultData = Intent()

        val request = PendingIntentHandler.retrieveProviderGetCredentialRequest(intent)
        val option = request?.credentialOptions?.filterIsInstance<GetDigitalCredentialOption>()?.firstOrNull()
        if (request == null || option == null) { finishError(resultData, "no digital credential request"); return }

        val origin = DcApiRequest.originOf(request, allowlist())
        LogStore.log("DC API request · origin=$origin · protocols=${DcApiRequest.protocolsOffered(option.requestJson)}")

        // The wallet assembles asynchronously (trust anchors from the trusted lists on first launch).
        lifecycleScope.launch {
            val wallet = DemoWallet.get(this@GetCredentialActivity)

            // org-iso-mdoc (ISO 18013-7): raw mdoc DeviceRequest → HPKE-encrypted DeviceResponse.
            val mdoc = DcApiRequest.matchProtocol(option.requestJson, listOf("org-iso-mdoc", "org.iso.mdoc"))
            if (mdoc != null) {
                val (proto, data) = mdoc
                val items = runCatching {
                    DeviceRequest.decode(Base64.decode(data.getString("deviceRequest"), Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP)).docRequests.map { dr ->
                        ConsentItem(dr.docType, dr.requested.flatMap { (_, els) -> els.map { it.identifier } })
                    }
                }.getOrDefault(emptyList())
                showConsent(DcApiVerifier(origin, "In-app request", signedRequestVerified = false, wrprcVerified = null), items,
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
                return@launch
            }

            val openid4vp = DcApiRequest.extractOpenId4Vp(option.requestJson)
            if (openid4vp == null) { finishError(resultData, "no openid4vp request"); return@launch }

            runCatching {
                val session = wallet.presentation.startDcApi(openid4vp, origin)
                val resolved = session.state.first { it is PresentationState.RequestResolved || it is PresentationState.Failed }
                if (resolved is PresentationState.Failed) throw resolved.error
                val presentation = (resolved as PresentationState.RequestResolved).request
                LogStore.log("DC API verifier=${presentation.verifier.clientId} · satisfiable=${presentation.satisfiable}")
                val items = presentation.queries.map { q ->
                    ConsentItem(q.queryId, q.candidates.firstOrNull()?.disclosedPaths?.map { it.last() } ?: listOf("no matching credential"))
                }
                val v = presentation.verifier
                val reg = v.registration
                val rpName = reg?.subjectName ?: reg?.subject?.takeIf { it.isNotBlank() } ?: v.commonName ?: v.clientId
                val subtitle = reg?.intermediaryName?.let { "via $it" } ?: "In-app request"
                val wrprc = reg?.let { it.attested || it.registrarVerified }
                showConsent(DcApiVerifier(rpName, subtitle, v.trusted, wrprc), items,
                    onApprove = {
                        lifecycleScope.launch {
                            runCatching {
                                session.respond(PresentationSelection.auto(presentation))
                                when (val done = session.state.first { it.isTerminal }) {
                                    is PresentationState.Completed -> returnDcApiResponse(resultData, done.dcApiResponse)
                                    is PresentationState.Failed -> throw done.error
                                    else -> error("unexpected terminal state $done")
                                }
                            }.onFailure { finishError(resultData, it.message) }
                        }
                    },
                    onDecline = { finishError(resultData, "declined by user") })
            }.onFailure { finishError(resultData, it.message) }
        }
    }

    private fun returnDcApiResponse(resultData: Intent, response: String?) {
        runCatching {
            DcApiResult.setResponse(resultData, response ?: error("no DC API response produced"))
            LogStore.log("✅ DC API response returned to caller")
            setResult(RESULT_OK, resultData)
        }.onFailure { finishExceptionData(resultData, it.message) }
        finish()
    }

    private fun showConsent(verifier: DcApiVerifier, items: List<ConsentItem>, onApprove: () -> Unit, onDecline: () -> Unit) {
        setContent { WalletTheme { DcApiConsentSheet(verifier, items, onApprove, onDecline) } }
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
