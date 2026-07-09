package com.hopae.eudi.wallet.vci

import com.hopae.eudi.wallet.sdjwt.JsonValue

/* OpenID4VCI 1.0 wire models, parsed from the SDK's own JsonValue. */

private fun JsonValue.Obj.str(name: String): String? = (this[name] as? JsonValue.Str)?.value
private fun JsonValue.Obj.requireStr(name: String, where: String): String =
    str(name) ?: throw VciException.ProtocolError("$where: missing '$name'")
private fun JsonValue.Obj.arrStr(name: String): List<String>? =
    (this[name] as? JsonValue.Arr)?.items?.map { (it as? JsonValue.Str)?.value ?: return null }

/** Credential offer (OpenID4VCI §4.1). */
class CredentialOffer(
    val credentialIssuer: String,
    val credentialConfigurationIds: List<String>,
    val preAuthorizedCode: String?,
    val txCode: TxCodeSpec?,
    val authorizationCodeIssuerState: String?,
) {
    /**
     * The Transaction Code input hints from a Credential Offer (OpenID4VCI §4.1.1). These describe how
     * the wallet should render the code-entry screen; they are guidance, not a wire constraint, so the
     * SDK never rejects a supplied code on their basis — [violations] lets the host surface a warning.
     */
    class TxCodeSpec(val length: Int?, val inputMode: String?, val description: String?) {
        /**
         * The ways [code] departs from these hints (empty = consistent). Advisory only: `input_mode`
         * `numeric` means digits only, `text` accepts anything, and `length` is the expected character
         * count. Never throws — a wallet may warn, or send the code regardless and let the issuer decide.
         */
        fun violations(code: String): List<String> = buildList {
            val mode = inputMode ?: "numeric" // §4.1.1: numeric is the default
            if (mode == "numeric" && !code.all { it.isDigit() }) {
                add("transaction code must contain only digits (input_mode=numeric)")
            }
            length?.let { if (code.length != it) add("transaction code should be $it characters, got ${code.length}") }
        }
    }

    companion object {
        fun parse(json: String): CredentialOffer =
            fromObj(JsonValue.parse(json) as? JsonValue.Obj ?: throw VciException.InvalidOffer("not an object"))

        fun fromObj(o: JsonValue.Obj): CredentialOffer {
            val issuer = o.str("credential_issuer") ?: throw VciException.InvalidOffer("missing credential_issuer")
            val ids = o.arrStr("credential_configuration_ids")
                ?: throw VciException.InvalidOffer("missing credential_configuration_ids")
            if (ids.isEmpty()) throw VciException.InvalidOffer("credential_configuration_ids is empty")

            val grants = o["grants"] as? JsonValue.Obj
            val preAuth = grants?.get("urn:ietf:params:oauth:grant-type:pre-authorized_code") as? JsonValue.Obj
            val authCode = grants?.get("authorization_code") as? JsonValue.Obj

            val txCode = (preAuth?.get("tx_code") as? JsonValue.Obj)?.let {
                TxCodeSpec(
                    length = (it["length"] as? JsonValue.NumInt)?.value?.toInt(),
                    inputMode = (it["input_mode"] as? JsonValue.Str)?.value,
                    description = (it["description"] as? JsonValue.Str)?.value,
                )
            }

            return CredentialOffer(
                credentialIssuer = issuer,
                credentialConfigurationIds = ids,
                preAuthorizedCode = preAuth?.str("pre-authorized_code"),
                txCode = txCode,
                authorizationCodeIssuerState = authCode?.str("issuer_state"),
            )
        }
    }
}

/**
 * The issuer's `credential_response_encryption` metadata (OpenID4VCI §12.2.4): which JWE algorithms it
 * can encrypt Credential Responses with, and whether encryption is mandatory.
 */
class ResponseEncryptionMetadata(
    val algValuesSupported: List<String>,
    val encValuesSupported: List<String>,
    val encryptionRequired: Boolean,
) {
    companion object {
        fun fromObj(o: JsonValue.Obj) = ResponseEncryptionMetadata(
            algValuesSupported = o.arrStr("alg_values_supported") ?: emptyList(),
            encValuesSupported = o.arrStr("enc_values_supported") ?: emptyList(),
            encryptionRequired = (o["encryption_required"] as? JsonValue.Bool)?.value ?: false,
        )
    }
}

/**
 * The issuer's `credential_request_encryption` metadata: the public keys a Credential Request may be
 * encrypted to. §8.2 makes request encryption mandatory whenever a `credential_response_encryption`
 * object is sent, so that an attacker cannot substitute the wallet's response-encryption key.
 */
class RequestEncryptionMetadata(
    /** Raw JWKs — `alg` (§10 requires it) and `kid` matter, so the parsed EC key alone is not enough. */
    val jwks: List<JsonValue.Obj>,
    val encValuesSupported: List<String>,
    val encryptionRequired: Boolean,
) {
    companion object {
        fun fromObj(o: JsonValue.Obj) = RequestEncryptionMetadata(
            jwks = ((o["jwks"] as? JsonValue.Obj)?.get("keys") as? JsonValue.Arr)?.items?.filterIsInstance<JsonValue.Obj>()
                ?: emptyList(),
            encValuesSupported = o.arrStr("enc_values_supported") ?: emptyList(),
            encryptionRequired = (o["encryption_required"] as? JsonValue.Bool)?.value ?: false,
        )
    }
}

/** Credential issuer metadata (OpenID4VCI §12.2). */
class CredentialIssuerMetadata(
    val credentialIssuer: String,
    val credentialEndpoint: String,
    val nonceEndpoint: String?,
    val deferredCredentialEndpoint: String?,
    val notificationEndpoint: String?,
    val authorizationServers: List<String>,
    val credentialConfigurationsSupported: Map<String, CredentialConfiguration>,
    /** Issuer display name (first `display` entry), if advertised. */
    val issuerDisplayName: String? = null,
    val credentialResponseEncryption: ResponseEncryptionMetadata? = null,
    val credentialRequestEncryption: RequestEncryptionMetadata? = null,
) {
    companion object {
        fun fromObj(o: JsonValue.Obj): CredentialIssuerMetadata {
            val issuer = o.requireStr("credential_issuer", "issuer metadata")
            val issuerDisplay = (o["display"] as? JsonValue.Arr)?.items?.firstOrNull() as? JsonValue.Obj
            val configs = (o["credential_configurations_supported"] as? JsonValue.Obj)?.entries
                ?.associate { (id, v) ->
                    id to CredentialConfiguration.fromObj(
                        v as? JsonValue.Obj ?: throw VciException.MetadataError("config '$id' not an object")
                    )
                } ?: emptyMap()
            return CredentialIssuerMetadata(
                credentialIssuer = issuer,
                credentialEndpoint = o.requireStr("credential_endpoint", "issuer metadata"),
                nonceEndpoint = o.str("nonce_endpoint"),
                deferredCredentialEndpoint = o.str("deferred_credential_endpoint"),
                notificationEndpoint = o.str("notification_endpoint"),
                authorizationServers = o.arrStr("authorization_servers") ?: listOf(issuer),
                credentialConfigurationsSupported = configs,
                issuerDisplayName = (issuerDisplay?.get("name") as? JsonValue.Str)?.value,
                credentialResponseEncryption = (o["credential_response_encryption"] as? JsonValue.Obj)
                    ?.let { ResponseEncryptionMetadata.fromObj(it) },
                credentialRequestEncryption = (o["credential_request_encryption"] as? JsonValue.Obj)
                    ?.let { RequestEncryptionMetadata.fromObj(it) },
            )
        }
    }
}

class CredentialConfiguration(
    val format: String,
    val vct: String?,
    val docType: String?,
    val proofSigningAlgs: List<String>,
    val scope: String?,
    /** From the first `display` entry — for wallet UI. */
    val displayName: String? = null,
    val logoUri: String? = null,
    val backgroundColor: String? = null,
) {
    companion object {
        fun fromObj(o: JsonValue.Obj): CredentialConfiguration {
            val proofAlgs = ((o["proof_types_supported"] as? JsonValue.Obj)
                ?.get("jwt") as? JsonValue.Obj)
                ?.let { (it["proof_signing_alg_values_supported"] as? JsonValue.Arr) }
                ?.items?.mapNotNull { (it as? JsonValue.Str)?.value } ?: emptyList()
            val display = (o["display"] as? JsonValue.Arr)?.items?.firstOrNull() as? JsonValue.Obj
            return CredentialConfiguration(
                format = (o["format"] as? JsonValue.Str)?.value ?: "",
                vct = (o["vct"] as? JsonValue.Str)?.value,
                docType = (o["doctype"] as? JsonValue.Str)?.value,
                proofSigningAlgs = proofAlgs,
                scope = (o["scope"] as? JsonValue.Str)?.value,
                displayName = (display?.get("name") as? JsonValue.Str)?.value,
                logoUri = ((display?.get("logo") as? JsonValue.Obj)?.get("uri") as? JsonValue.Str)?.value,
                backgroundColor = (display?.get("background_color") as? JsonValue.Str)?.value,
            )
        }
    }
}

/** Authorization server metadata (RFC 8414) — the fields we use. */
class AuthorizationServerMetadata(
    val issuer: String,
    val tokenEndpoint: String,
    val pushedAuthorizationRequestEndpoint: String?,
    val authorizationEndpoint: String?,
    val dpopSigningAlgValuesSupported: List<String>,
) {
    companion object {
        fun fromObj(o: JsonValue.Obj): AuthorizationServerMetadata = AuthorizationServerMetadata(
            issuer = o.requireStr("issuer", "AS metadata"),
            tokenEndpoint = o.requireStr("token_endpoint", "AS metadata"),
            pushedAuthorizationRequestEndpoint = o.str("pushed_authorization_request_endpoint"),
            authorizationEndpoint = o.str("authorization_endpoint"),
            dpopSigningAlgValuesSupported = o.arrStr("dpop_signing_alg_values_supported") ?: emptyList(),
        )
    }
}

class TokenResponse(
    val accessToken: String,
    val tokenType: String,
    val cNonce: String?,
    val expiresIn: Long?,
    val authorizationDetails: JsonValue?,
    /**
     * §8.2: the `credential_identifiers` the issuer bound to each `credential_configuration_id` in the
     * token-response `authorization_details`. When a config appears here, its Credential Request MUST use
     * one of these `credential_identifier`s instead of the `credential_configuration_id`. Empty when the
     * issuer returned no `authorization_details` (e.g. a scope-based authorization).
     */
    val credentialIdentifiers: Map<String, List<String>>,
    /** OAuth 2.0 refresh token (RFC 6749 §5.1) — enables reissuance without re-authorization. */
    val refreshToken: String?,
) {
    companion object {
        fun fromObj(o: JsonValue.Obj): TokenResponse = TokenResponse(
            accessToken = o.requireStr("access_token", "token response"),
            tokenType = o.requireStr("token_type", "token response"),
            cNonce = o.str("c_nonce"),
            expiresIn = (o["expires_in"] as? JsonValue.NumInt)?.value,
            authorizationDetails = o["authorization_details"],
            credentialIdentifiers = parseCredentialIdentifiers(o["authorization_details"]),
            refreshToken = o.str("refresh_token"),
        )

        /** Maps each `authorization_details[].credential_configuration_id` to its non-empty `credential_identifiers`. */
        private fun parseCredentialIdentifiers(details: JsonValue?): Map<String, List<String>> =
            (details as? JsonValue.Arr)?.items.orEmpty().filterIsInstance<JsonValue.Obj>().mapNotNull { entry ->
                val configId = (entry["credential_configuration_id"] as? JsonValue.Str)?.value ?: return@mapNotNull null
                val ids = (entry["credential_identifiers"] as? JsonValue.Arr)?.items
                    ?.mapNotNull { (it as? JsonValue.Str)?.value }.orEmpty()
                if (ids.isEmpty()) null else configId to ids
            }.toMap()
    }
}

/** One issued credential plus optional deferral. */
class IssuedCredential(val format: String, val credential: String)

class CredentialResponse(
    val credentials: List<IssuedCredential>,
    val transactionId: String?,
    val notificationId: String?,
    /**
     * The `interval` (§8.3): the minimum seconds the wallet SHOULD wait before re-polling the deferred
     * endpoint. REQUIRED alongside `transaction_id`; null when the credential was issued immediately.
     */
    val interval: Long? = null,
    /** Context for follow-ups (deferred poll, notification, reissuance) — set by the client, not parsed. */
    val accessToken: String? = null,
    val credentialIssuer: String? = null,
    val requestedFormat: String = "dc+sd-jwt",
    /** Refresh token + config id — persist these to reissue (renew) the credential later. */
    val refreshToken: String? = null,
    val configurationId: String? = null,
) {
    /** True when the issuer deferred issuance (returned a transaction_id, no credential yet). */
    val isDeferred: Boolean get() = credentials.isEmpty() && transactionId != null

    /** True when the issuer granted a refresh token, so [Openid4VciClient.reissue] can renew later. */
    val canReissue: Boolean get() = refreshToken != null && credentialIssuer != null && configurationId != null

    internal fun withContext(
        accessToken: String?, credentialIssuer: String?, requestedFormat: String,
        refreshToken: String? = null, configurationId: String? = null,
    ) = CredentialResponse(credentials, transactionId, notificationId, interval, accessToken, credentialIssuer, requestedFormat, refreshToken, configurationId)

    companion object {
        fun fromObj(o: JsonValue.Obj, requestedFormat: String): CredentialResponse {
            // OpenID4VCI 1.0: "credentials" is an array of objects each with a "credential" member.
            val creds = (o["credentials"] as? JsonValue.Arr)?.items?.mapNotNull { item ->
                val c = (item as? JsonValue.Obj)?.get("credential")
                when (c) {
                    is JsonValue.Str -> IssuedCredential(requestedFormat, c.value)
                    else -> null
                }
            } ?: emptyList()
            return CredentialResponse(
                credentials = creds,
                transactionId = o.str("transaction_id"),
                notificationId = o.str("notification_id"),
                interval = (o["interval"] as? JsonValue.NumInt)?.value,
            )
        }
    }
}
