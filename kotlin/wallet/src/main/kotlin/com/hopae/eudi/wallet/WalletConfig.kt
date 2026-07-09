package com.hopae.eudi.wallet

import com.hopae.eudi.wallet.mdoc.MdocDeviceAuthMode

/**
 * Immutable wallet configuration. HAIP defaults (PAR/DPoP Required) live in the sub-configs.
 * Trust anchors are passed as DER so the public API stays free of trust-module types.
 */
class WalletConfig(
    val issuance: IssuanceConfig = IssuanceConfig(),
    val presentation: PresentationConfig = PresentationConfig(),
    val trust: TrustConfig = TrustConfig(),
    val transactionLog: TransactionLogConfig = TransactionLogConfig(),
)

/** Audit / transaction-log behaviour. */
class TransactionLogConfig(
    /**
     * Also record presentations that fail during submission, with [TransactionStatus.ERROR][com.hopae.eudi.wallet.txlog.TransactionStatus].
     * Default false — only successful and declined presentations are logged.
     */
    val recordFailures: Boolean = false,
)

class IssuanceConfig(
    val clientId: String = "wallet-dev",
    /** OAuth redirect URI for the authorization-code grant (the app registers this scheme). */
    val redirectUri: String = "eudi-wallet://authorize",
    // Later: clientAuth (None | AttestationBased), par/dpop policy.
)

class PresentationConfig(
    /**
     * How this wallet's mdoc credentials authenticate a response (ISO 18013-5 §9.1.3.5), for both
     * proximity and OpenID4VP. [MdocDeviceAuthMode.Mac] requires the credential's `DeviceKey` to be a
     * key-agreement key — on Android Keystore that purpose is fixed at key creation, so switching an
     * existing wallet over needs re-issued credentials. Over OpenID4VP it additionally needs the verifier
     * to request `deviceMac` (an encrypted response supplying an `EReaderKey`); otherwise the wallet
     * falls back to `deviceSignature`.
     */
    val mdocDeviceAuth: MdocDeviceAuthMode = MdocDeviceAuthMode.Signature,
    // Phase C: clientIdPrefixes, responseEncryption.
)

/** Trust anchors as DER — the facade builds trust validators internally per port. */
class TrustConfig(
    val issuerAnchorsDer: List<ByteArray> = emptyList(),
    val readerAnchorsDer: List<ByteArray> = emptyList(),
)
