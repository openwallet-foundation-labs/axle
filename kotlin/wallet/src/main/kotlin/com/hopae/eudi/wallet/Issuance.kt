package com.hopae.eudi.wallet

import com.hopae.eudi.wallet.spi.CredentialId
import com.hopae.eudi.wallet.spi.CredentialPolicy
import com.hopae.eudi.wallet.spi.KeySpec

/** A resolved credential offer (OpenID4VCI §4) — the first step of the 2-phase issuance flow. */
class CredentialOffer internal constructor(internal val raw: com.hopae.eudi.wallet.vci.CredentialOffer) {
    val credentialIssuer: String get() = raw.credentialIssuer
    val credentialConfigurationIds: List<String> get() = raw.credentialConfigurationIds
    val requiresTxCode: Boolean get() = raw.txCode != null
}

/** What to issue: which offered config, key material policy, and (if pre-known) the tx_code. */
class IssuanceRequest private constructor(
    internal val offer: CredentialOffer,
    internal val configurationId: String,
    internal val txCode: String?,
    internal val keySpec: KeySpec,
    internal val policy: CredentialPolicy,
) {
    companion object {
        fun fromOffer(
            offer: CredentialOffer,
            configurationId: String,
            txCode: String? = null,
            keySpec: KeySpec = KeySpec(),
            policy: CredentialPolicy = CredentialPolicy(),
        ): IssuanceRequest = IssuanceRequest(offer, configurationId, txCode, keySpec, policy)
    }
}

/** Terminal issuance outcome (credentials stored; ids for follow-up). */
data class IssuanceResult(val issued: List<CredentialId>)

/** Issuance session state (API-CONTRACT.md §6.1). auth-code/tx-code interruptions arrive in later slices. */
sealed interface IssuanceState {
    data object Preparing : IssuanceState
    data class AuthorizationRequired(val authorizationUrl: String) : IssuanceState
    data object TxCodeRequired : IssuanceState
    data object Processing : IssuanceState
    data class Completed(val result: IssuanceResult) : IssuanceState
    data class Failed(val error: WalletError.Issuance) : IssuanceState

    val isTerminal: Boolean get() = this is Completed || this is Failed
}
