package com.hopae.eudi.wallet.android.dcapi

import android.content.Intent
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
     *
     * Prefer [matchProtocol]: it returns the exchange protocol identifier alongside the data, and passing that
     * to `startDcApi` lets the SDK check the request shape against what the verifier announced.
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
     * The credentials the User picked in the OS selector — the `documentId`s the matcher database registered,
     * which [DcApiRegistrar] fills with `Credential.id.value`. Empty when the platform named none.
     *
     * The Credential Manager resolves the choice *before* this Activity is started and never re-asks, so this
     * is the only place the pick exists. [ProviderGetCredentialRequest] does not carry it, and neither does
     * GMS's `IntentHelper.EXTRA_CREDENTIAL_ID` on this path — the registry provider hands the selection over
     * as its own Intent extras:
     *
     * ```
     * action                          androidx.credentials.registry.provider.action.GET_CREDENTIAL
     * …extra.CREDENTIAL_SET_ID        "0 openid4vp-v1-unsigned"
     * …extra.CREDENTIAL_SET_ELEMENT_LENGTH  1
     * …extra.CREDENTIAL_SET_ELEMENT_ID_0    "0 openid4vp-v1-unsigned cred-dnYLk7IXhHRsg1KY"
     * ```
     *
     * An element id is the set id followed by the credential id, so the credential id is what remains once the
     * `CREDENTIAL_SET_ID` prefix is stripped (falling back to the last whitespace-separated token). A *set* can
     * hold more than one element — one per credential of a combination answering a multi-credential request —
     * which is why this returns a list rather than a single id.
     *
     * A wallet that ignores these answers with whatever candidate it happens to find first: a substitution the
     * User cannot detect, because the selector showed them a different credential. That is exactly the case
     * when the wallet holds several credentials of one type — the only case where the selector matters.
     */
    fun selectedCredentialIds(intent: Intent): List<String> {
        val setId = intent.getStringExtra(EXTRA_CREDENTIAL_SET_ID)
        val length = intent.getIntExtra(EXTRA_CREDENTIAL_SET_ELEMENT_LENGTH, 0)
        return (0 until length).mapNotNull { i ->
            val element = intent.getStringExtra("$EXTRA_CREDENTIAL_SET_ELEMENT_ID_PREFIX$i") ?: return@mapNotNull null
            val id = if (setId != null && element.startsWith("$setId ")) element.removePrefix("$setId ")
            else element.substringAfterLast(' ')
            id.trim().takeIf { it.isNotEmpty() }
        }
    }

    private const val EXTRA_CREDENTIAL_SET_ID = "androidx.credentials.registry.provider.extra.CREDENTIAL_SET_ID"
    private const val EXTRA_CREDENTIAL_SET_ELEMENT_LENGTH = "androidx.credentials.registry.provider.extra.CREDENTIAL_SET_ELEMENT_LENGTH"
    private const val EXTRA_CREDENTIAL_SET_ELEMENT_ID_PREFIX = "androidx.credentials.registry.provider.extra.CREDENTIAL_SET_ELEMENT_ID_"

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
