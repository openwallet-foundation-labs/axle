@file:OptIn(androidx.credentials.ExperimentalDigitalCredentialApi::class)

package com.hopae.eudi.demo

import android.content.Intent
import android.os.Bundle
import android.util.Base64
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.credentials.DigitalCredential
import androidx.credentials.GetCredentialResponse
import androidx.credentials.GetDigitalCredentialOption
import androidx.credentials.exceptions.GetCredentialUnknownException
import androidx.credentials.provider.PendingIntentHandler
import androidx.credentials.provider.ProviderGetCredentialRequest
import androidx.lifecycle.lifecycleScope
import com.hopae.eudi.wallet.PresentationSelection
import com.hopae.eudi.wallet.PresentationState
import com.hopae.eudi.wallet.mdoc.DeviceRequest
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import org.json.JSONObject
import java.security.MessageDigest

/**
 * Handles a Digital Credentials API (OpenID4VP) request routed to this wallet by the Credential
 * Manager. Extracts the request JSON + caller origin, runs it through the SDK's [startDcApi], and
 * returns the response object. No UI — the OS selector already mediated the user's choice.
 */
class GetCredentialActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val wallet = DemoWallet.get(this)
        val resultData = Intent()

        val request = PendingIntentHandler.retrieveProviderGetCredentialRequest(intent)
        val option = request?.credentialOptions?.filterIsInstance<GetDigitalCredentialOption>()?.firstOrNull()
        if (request == null || option == null) {
            fail(resultData, "no digital credential request")
            return
        }

        val origin = originOf(request)

        // org-iso-mdoc (ISO 18013-7): raw mdoc DeviceRequest → HPKE-encrypted DeviceResponse.
        val mdoc = matchProtocol(option.requestJson, listOf("org-iso-mdoc", "org.iso.mdoc"))
        if (mdoc != null) {
            val (proto, data) = mdoc
            LogStore.log("DC API [$proto] request · origin=$origin")
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
                            val content = JSONObject().put("protocol", proto).put("data", JSONObject().put("response", response))
                            PendingIntentHandler.setGetCredentialResponse(resultData, GetCredentialResponse(DigitalCredential(content.toString())))
                            LogStore.log("✅ DC API (mdoc) response returned to caller")
                            setResult(RESULT_OK, resultData)
                        }.onFailure { failException(resultData, it.message) }
                        finish()
                    }
                },
                onDecline = { LogStore.log("DC API (mdoc) declined by user"); failException(resultData, "declined by user"); finish() })
            return
        }

        val openid4vp = extractOpenId4Vp(option.requestJson)
        if (openid4vp == null) {
            LogStore.log("DC API: no openid4vp request in envelope: ${option.requestJson.take(200)}")
            failException(resultData, "no openid4vp request"); finish(); return
        }
        LogStore.log("DC API request · origin=$origin")

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
                                        val response = done.dcApiResponse ?: error("no DC API response produced")
                                        PendingIntentHandler.setGetCredentialResponse(resultData, GetCredentialResponse(DigitalCredential(response)))
                                        LogStore.log("✅ DC API response returned to caller")
                                        setResult(RESULT_OK, resultData)
                                    }
                                    is PresentationState.Failed -> throw done.error
                                    else -> error("unexpected terminal state $done")
                                }
                            }.onFailure { failException(resultData, it.message) }
                            finish()
                        }
                    },
                    onDecline = { LogStore.log("DC API declined by user"); failException(resultData, "declined by user"); finish() })
            }.onFailure { failException(resultData, it.message); finish() }
        }
    }

    private fun showConsent(verifier: String, trusted: Boolean, items: List<ConsentItem>, onApprove: () -> Unit, onDecline: () -> Unit) {
        setContent { DcApiConsentScreen(verifier, trusted, items, onApprove, onDecline) }
    }

    /**
     * The DC API request is an envelope `{"requests":[{"protocol","data"},…]}`; pull out the OpenID4VP
     * request object (preferring unsigned) that the SDK's [startDcApi] understands. Falls back to the raw
     * JSON if it's already a flat request.
     */
    /** Returns the (protocol, data) of the first request in the envelope matching one of [protocols]. */
    private fun matchProtocol(requestJson: String, protocols: List<String>): Pair<String, JSONObject>? {
        val requests = runCatching { JSONObject(requestJson) }.getOrNull()?.optJSONArray("requests") ?: return null
        for (proto in protocols) {
            for (i in 0 until requests.length()) {
                val req = requests.optJSONObject(i) ?: continue
                if (req.optString("protocol") == proto) return (req.optJSONObject("data") ?: continue).let { proto to it }
            }
        }
        return null
    }

    private fun extractOpenId4Vp(requestJson: String): String? {
        val root = runCatching { JSONObject(requestJson) }.getOrNull() ?: return null
        val requests = root.optJSONArray("requests") ?: return requestJson
        for (proto in listOf("openid4vp-v1-unsigned", "openid4vp-v1-signed", "openid4vp")) {
            for (i in 0 until requests.length()) {
                val req = requests.optJSONObject(i) ?: continue
                if (req.optString("protocol") == proto) return req.get("data").toString()
            }
        }
        return null
    }

    /** Web origin for privileged callers (browsers in the allowlist); otherwise the app's signing hash. */
    private fun originOf(request: ProviderGetCredentialRequest): String {
        val allowlist = runCatching {
            assets.open("privileged_allowlist.json").bufferedReader().use { it.readText() }
        }.getOrDefault("""{"apps":[]}""")
        runCatching { request.callingAppInfo.getOrigin(allowlist) }.getOrNull()?.let { return it }
        val cert = runCatching {
            request.callingAppInfo.signingInfoCompat.signingCertificateHistory.first().toByteArray()
        }.getOrNull() ?: return "android:apk-key-hash:unknown"
        val hash = Base64.encodeToString(MessageDigest.getInstance("SHA-256").digest(cert), Base64.NO_WRAP or Base64.NO_PADDING)
        return "android:apk-key-hash:$hash"
    }

    private fun fail(resultData: Intent, message: String) {
        failException(resultData, message)
        finish()
    }

    private fun failException(resultData: Intent, message: String?) {
        LogStore.log("❌ DC API: ${message ?: "error"}")
        PendingIntentHandler.setGetCredentialException(resultData, GetCredentialUnknownException(message ?: "error"))
        setResult(RESULT_OK, resultData)
    }
}
