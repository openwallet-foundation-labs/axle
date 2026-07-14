package com.hopae.eudi.wallet.android.dcapi

import android.util.Base64
import androidx.credentials.provider.ProviderGetCredentialRequest
import org.json.JSONObject
import java.security.MessageDigest

/**
 * Stateless helpers for a Digital Credentials API request routed to the wallet by the Credential Manager —
 * the UI-less plumbing an app's request-handling Activity needs. The Activity, its consent UI, and the
 * privileged-caller allowlist stay in the app.
 */
object DcApiRequest {

    /** The (protocol, data) of the first request in the DC API envelope matching one of [protocols], or null. */
    fun matchProtocol(requestJson: String, protocols: List<String>): Pair<String, JSONObject>? {
        val requests = runCatching { JSONObject(requestJson) }.getOrNull()?.optJSONArray("requests") ?: return null
        for (proto in protocols) {
            for (i in 0 until requests.length()) {
                val req = requests.optJSONObject(i) ?: continue
                if (req.optString("protocol") == proto) return (req.optJSONObject("data") ?: continue).let { proto to it }
            }
        }
        return null
    }

    /** The protocols advertised in the DC API envelope (for tracing / diagnostics). */
    fun protocolsOffered(requestJson: String): List<String> {
        val requests = runCatching { JSONObject(requestJson) }.getOrNull()?.optJSONArray("requests") ?: return emptyList()
        return (0 until requests.length()).mapNotNull { requests.optJSONObject(it)?.optString("protocol") }
    }

    /**
     * The OpenID4VP request object (preferring unsigned) the SDK's `startDcApi` understands, pulled from the
     * `{"requests":[{protocol,data},…]}` envelope. Falls back to the raw JSON if it is already a flat request.
     */
    fun extractOpenId4Vp(requestJson: String): String? {
        val root = runCatching { JSONObject(requestJson) }.getOrNull() ?: return null
        val requests = root.optJSONArray("requests") ?: return requestJson
        for (proto in listOf("openid4vp-v1-unsigned", "openid4vp-v1-signed")) {
            for (i in 0 until requests.length()) {
                val req = requests.optJSONObject(i) ?: continue
                if (req.optString("protocol") == proto) return req.get("data").toString()
            }
        }
        return null
    }

    /**
     * The web origin to bind the presentation to: the privileged caller's origin (browsers in [allowlistJson],
     * the app-owned `privileged_allowlist.json`), else the calling app's `android:apk-key-hash:` signing hash.
     */
    fun originOf(request: ProviderGetCredentialRequest, allowlistJson: String): String {
        runCatching { request.callingAppInfo.getOrigin(allowlistJson) }.getOrNull()?.let { return it }
        val cert = runCatching {
            request.callingAppInfo.signingInfoCompat.signingCertificateHistory.first().toByteArray()
        }.getOrNull() ?: return "android:apk-key-hash:unknown"
        val hash = Base64.encodeToString(MessageDigest.getInstance("SHA-256").digest(cert), Base64.NO_WRAP or Base64.NO_PADDING)
        return "android:apk-key-hash:$hash"
    }
}
