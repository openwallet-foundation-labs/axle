@file:OptIn(androidx.credentials.ExperimentalDigitalCredentialApi::class)

package com.hopae.eudi.demo

import android.content.Intent
import android.os.Bundle
import android.util.Base64
import androidx.activity.ComponentActivity
import androidx.credentials.DigitalCredential
import androidx.credentials.GetCredentialResponse
import androidx.credentials.GetDigitalCredentialOption
import androidx.credentials.exceptions.GetCredentialUnknownException
import androidx.credentials.provider.PendingIntentHandler
import androidx.credentials.provider.ProviderGetCredentialRequest
import androidx.lifecycle.lifecycleScope
import com.hopae.eudi.wallet.PresentationSelection
import com.hopae.eudi.wallet.PresentationState
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
    }

    /**
     * The DC API request is an envelope `{"requests":[{"protocol","data"},…]}`; pull out the OpenID4VP
     * request object (preferring unsigned) that the SDK's [startDcApi] understands. Falls back to the raw
     * JSON if it's already a flat request.
     */
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
