package com.hopae.eudi.wallet

import com.hopae.eudi.wallet.sdjwt.JsonValue
import com.hopae.eudi.wallet.spi.CredentialPolicy
import com.hopae.eudi.wallet.spi.KeyHandle
import com.hopae.eudi.wallet.spi.KeyUse
import com.hopae.eudi.wallet.spi.SecureAreaId
import com.hopae.eudi.wallet.vci.CredentialResponse

/**
 * Everything needed to resume a credential after issuance — deferred poll, reissue, notification —
 * across app restarts (assembly gap #3). Persisted as JSON in the envelope (deferred) or a storage
 * collection (reissue). Key material stays in the SecureArea; only handles are serialized.
 */
internal class FollowUpContext(
    val credentialIssuer: String,
    val configurationId: String,
    val requestedFormat: String,
    val accessToken: String?,
    val refreshToken: String?,
    val transactionId: String?,
    val notificationId: String?,
    val proofKeys: List<KeyHandle>,
    val dpopKey: KeyHandle,
    val policy: CredentialPolicy,
) {
    /** A copy with a fresh `transaction_id` — the issuer rotates it on each still-deferred (202) response. */
    fun withTransactionId(transactionId: String?): FollowUpContext = FollowUpContext(
        credentialIssuer, configurationId, requestedFormat, accessToken, refreshToken,
        transactionId, notificationId, proofKeys, dpopKey, policy,
    )

    /** Reconstructs the vci [CredentialResponse] carrying the follow-up context (public ctor, no `withContext`). */
    fun toCredentialResponse(): CredentialResponse = CredentialResponse(
        credentials = emptyList(),
        transactionId = transactionId,
        notificationId = notificationId,
        accessToken = accessToken,
        credentialIssuer = credentialIssuer,
        requestedFormat = requestedFormat,
        refreshToken = refreshToken,
        configurationId = configurationId,
    )

    fun encode(): ByteArray = JsonValue.Obj(
        listOf(
            "credentialIssuer" to JsonValue.Str(credentialIssuer),
            "configurationId" to JsonValue.Str(configurationId),
            "requestedFormat" to JsonValue.Str(requestedFormat),
            "accessToken" to nullable(accessToken),
            "refreshToken" to nullable(refreshToken),
            "transactionId" to nullable(transactionId),
            "notificationId" to nullable(notificationId),
            "proofKeys" to JsonValue.Arr(proofKeys.map { it.toJson() }),
            "dpopKey" to dpopKey.toJson(),
            "batchSize" to JsonValue.NumInt(policy.batchSize.toLong()),
            "use" to JsonValue.Str(policy.use.name),
        ),
    ).serialize().encodeToByteArray()

    companion object {
        fun decode(bytes: ByteArray): FollowUpContext {
            val o = JsonValue.parse(bytes.decodeToString()) as JsonValue.Obj
            return FollowUpContext(
                credentialIssuer = o.str("credentialIssuer"),
                configurationId = o.str("configurationId"),
                requestedFormat = o.str("requestedFormat"),
                accessToken = o.strOrNull("accessToken"),
                refreshToken = o.strOrNull("refreshToken"),
                transactionId = o.strOrNull("transactionId"),
                notificationId = o.strOrNull("notificationId"),
                proofKeys = (o["proofKeys"] as JsonValue.Arr).items.map { keyHandle(it as JsonValue.Obj) },
                dpopKey = keyHandle(o["dpopKey"] as JsonValue.Obj),
                policy = CredentialPolicy((o["batchSize"] as JsonValue.NumInt).value.toInt(), KeyUse.valueOf(o.str("use"))),
            )
        }
    }
}

private fun nullable(value: String?): JsonValue = value?.let { JsonValue.Str(it) } ?: JsonValue.Null
private fun JsonValue.Obj.str(key: String): String = (this[key] as JsonValue.Str).value
private fun JsonValue.Obj.strOrNull(key: String): String? = (this[key] as? JsonValue.Str)?.value
private fun KeyHandle.toJson(): JsonValue = JsonValue.Obj(listOf("secureArea" to JsonValue.Str(secureArea.value), "alias" to JsonValue.Str(alias)))
private fun keyHandle(o: JsonValue.Obj): KeyHandle = KeyHandle(SecureAreaId(o.str("secureArea")), o.str("alias"))
