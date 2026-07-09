package com.hopae.eudi.wallet

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
     * How the mdoc authenticates a proximity response (ISO 18013-5 §9.1.3.5). [ProximityDeviceAuth.Mac]
     * requires the credential's `DeviceKey` to be a key-agreement key — on Android Keystore that purpose
     * is fixed at key creation, so switching an existing wallet over needs re-issued credentials.
     */
    val proximityDeviceAuth: ProximityDeviceAuth = ProximityDeviceAuth.Signature,
    // Phase C: clientIdPrefixes, responseEncryption.
)

/** ISO 18013-5 §9.1.3.5 device authentication forms. */
enum class ProximityDeviceAuth {
    /** `deviceSignature` — an ECDSA signature any third party can verify. */
    Signature,

    /**
     * `deviceMac` — an HMAC only this reader can check, since the key comes from a DeviceKey/EReaderKey
     * ECDH. Non-transferable: the reader cannot prove to anyone else that the mdoc answered.
     */
    Mac,
}

/** Trust anchors as DER — the facade builds trust validators internally per port. */
class TrustConfig(
    val issuerAnchorsDer: List<ByteArray> = emptyList(),
    val readerAnchorsDer: List<ByteArray> = emptyList(),
)
