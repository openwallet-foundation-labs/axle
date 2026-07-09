package com.hopae.eudi.wallet

import com.hopae.eudi.wallet.spi.CredentialId
import com.hopae.eudi.wallet.spi.CredentialPolicy
import com.hopae.eudi.wallet.spi.KeySpec

/**
 * The Transaction Code input hints from a Credential Offer (OpenID4VCI §4.1.1) — how to render the
 * code-entry screen. Guidance, not a wire constraint: [validate] returns any inconsistencies for the
 * host to warn about, but the SDK never rejects a code on their basis (a hint can be wrong; the issuer
 * is the authority).
 */
class TxCodeSpec internal constructor(private val raw: com.hopae.eudi.wallet.vci.CredentialOffer.TxCodeSpec) {
    /** Expected length, if advertised — for laying out the input field. */
    val length: Int? get() = raw.length

    /** `numeric` (digits only) or `text` (any characters); null means the §4.1.1 default, `numeric`. */
    val inputMode: String? get() = raw.inputMode

    /** How the End-User obtains the code (≤300 chars); show it next to the input. */
    val description: String? get() = raw.description

    /** The ways [code] departs from these hints (empty = consistent). Advisory — never blocks issuance. */
    fun validate(code: String): List<String> = raw.violations(code)
}

/** A resolved credential offer (OpenID4VCI §4) — the first step of the 2-phase issuance flow. */
class CredentialOffer internal constructor(internal val raw: com.hopae.eudi.wallet.vci.CredentialOffer) {
    val credentialIssuer: String get() = raw.credentialIssuer
    val credentialConfigurationIds: List<String> get() = raw.credentialConfigurationIds
    val requiresTxCode: Boolean get() = raw.txCode != null

    /** The transaction-code input hints (§4.1.1), or null when the offer needs no code. */
    val txCode: TxCodeSpec? get() = raw.txCode?.let { TxCodeSpec(it) }
}

/** What to issue: from an offer or wallet-initiated, plus key policy and (if pre-known) the tx_code. */
class IssuanceRequest private constructor(
    internal val source: Source,
    internal val configurationId: String,
    internal val txCode: String?,
    internal val keySpec: KeySpec,
    internal val policy: CredentialPolicy,
) {
    internal sealed interface Source {
        data class FromOffer(val offer: CredentialOffer) : Source
        data class FromIssuer(val credentialIssuer: String) : Source
    }

    companion object {
        /** 2-phase flow: issue an offered credential (pre-authorized or authorization-code grant). */
        fun fromOffer(
            offer: CredentialOffer,
            configurationId: String,
            txCode: String? = null,
            keySpec: KeySpec = KeySpec(),
            policy: CredentialPolicy = CredentialPolicy(),
        ): IssuanceRequest = IssuanceRequest(Source.FromOffer(offer), configurationId, txCode, keySpec, policy)

        /** Wallet-initiated issuance from an issuer (authorization-code grant, browser step required). */
        fun fromIssuer(
            credentialIssuer: String,
            configurationId: String,
            keySpec: KeySpec = KeySpec(),
            policy: CredentialPolicy = CredentialPolicy(),
        ): IssuanceRequest = IssuanceRequest(Source.FromIssuer(credentialIssuer), configurationId, null, keySpec, policy)
    }
}

/** Terminal issuance outcome (credentials stored; ids for follow-up). */
data class IssuanceResult(val issued: List<CredentialId>)

/** Issuance session state. auth-code/tx-code interruptions arrive in later slices. */
sealed interface IssuanceState {
    data object Preparing : IssuanceState
    data class AuthorizationRequired(val authorizationUrl: String) : IssuanceState
    /** The pre-authorized flow needs a transaction code; [txCode] carries the §4.1.1 input hints, if any. */
    data class TxCodeRequired(val txCode: TxCodeSpec? = null) : IssuanceState
    data object Processing : IssuanceState
    data class Completed(val result: IssuanceResult) : IssuanceState
    data class Failed(val error: WalletError.Issuance) : IssuanceState

    val isTerminal: Boolean get() = this is Completed || this is Failed
}
