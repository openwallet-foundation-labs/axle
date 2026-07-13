import CborCose
import Foundation
import MDoc
import OpenID4VP

/// Immutable wallet configuration. Trust anchors are passed as DER so the public API stays free of
/// trust-module types.
public struct WalletConfig {
    public let issuance: IssuanceConfig
    public let presentation: PresentationConfig
    public let trust: TrustConfig
    public let transactionLog: TransactionLogConfig

    public init(issuance: IssuanceConfig = IssuanceConfig(),
                presentation: PresentationConfig = PresentationConfig(),
                trust: TrustConfig = TrustConfig(),
                transactionLog: TransactionLogConfig = TransactionLogConfig()) {
        self.issuance = issuance
        self.presentation = presentation
        self.trust = trust
        self.transactionLog = transactionLog
    }
}

/// Audit / transaction-log behaviour.
public struct TransactionLogConfig {
    /// Also record presentations that fail during final submission, with `.error` status.
    /// Default false — only successful and declined presentations are logged.
    public let recordFailures: Bool
    public init(recordFailures: Bool = false) {
        self.recordFailures = recordFailures
    }
}

public struct IssuanceConfig {
    public let clientId: String
    /// OAuth redirect URI for the authorization-code grant (the app registers this scheme).
    public let redirectUri: String
    public init(clientId: String = "wallet-dev", redirectUri: String = "eudi-wallet://authorize") {
        self.clientId = clientId
        self.redirectUri = redirectUri
    }
}

public struct PresentationConfig {
    /// How this wallet's mdoc credentials authenticate a response (ISO 18013-5 §9.1.3.5), for both
    /// proximity and OpenID4VP. `.mac` requires the credential's `DeviceKey` to be a key-agreement key —
    /// on Android Keystore / Secure Enclave that purpose is fixed at key creation, so switching an existing
    /// wallet over needs re-issued credentials. Over OpenID4VP it additionally needs the verifier to request
    /// `deviceMac` (an encrypted response supplying an `EReaderKey`); otherwise it falls back to `deviceSignature`.
    public let mdocDeviceAuth: MdocDeviceAuthMode
    /// Maps an OpenID4VP `transaction_data` entry to the mdoc device-signed data element that protects it
    /// (ISO 18013-7 B.2.1). Nil (default) → the wallet rejects transaction_data bound to an mdoc, since the
    /// type→element mapping is credential-type specific and only the host knows it.
    public let mdocTransactionDataBinder: OpenID4VP.MdocTransactionDataBinder?
    /// ISO 18013-5 §9.1.5.2 Table 22: the curve of the ephemeral session key (EDeviceKey) for proximity. P-256
    /// (default), P-384 or P-521 — the reader matches whatever the mdoc offers. Remote OpenID4VP response
    /// encryption already follows the verifier's chosen curve, so no wallet setting is needed there.
    public let proximitySessionCurve: EcCurve
    public init(mdocDeviceAuth: MdocDeviceAuthMode = .signature,
                mdocTransactionDataBinder: OpenID4VP.MdocTransactionDataBinder? = nil,
                proximitySessionCurve: EcCurve = .p256) {
        self.mdocDeviceAuth = mdocDeviceAuth
        self.mdocTransactionDataBinder = mdocTransactionDataBinder
        self.proximitySessionCurve = proximitySessionCurve
    }
}

/// Trust anchors as DER — the facade builds trust validators internally per port.
public struct TrustConfig {
    public let issuerAnchorsDer: [[UInt8]]
    public let readerAnchorsDer: [[UInt8]]
    /// Registrar CA anchors: the WRPRC (RP registration cert, `rc-wrp+jwt`) and its status list chain to these.
    /// When set, a WRPRC carried in a request's `verifier_info` is validated and its revocation status checked.
    public let registrarAnchorsDer: [[UInt8]]
    public init(issuerAnchorsDer: [[UInt8]] = [], readerAnchorsDer: [[UInt8]] = [],
                registrarAnchorsDer: [[UInt8]] = []) {
        self.issuerAnchorsDer = issuerAnchorsDer
        self.readerAnchorsDer = readerAnchorsDer
        self.registrarAnchorsDer = registrarAnchorsDer
    }
}
