import Foundation

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
    /// How the mdoc authenticates a proximity response (ISO 18013-5 §9.1.3.5). `.mac` requires the
    /// credential's `DeviceKey` to be a key-agreement key — on Android Keystore / Secure Enclave that
    /// purpose is fixed at key creation, so switching an existing wallet over needs re-issued credentials.
    public let proximityDeviceAuth: ProximityDeviceAuth
    public init(proximityDeviceAuth: ProximityDeviceAuth = .signature) {
        self.proximityDeviceAuth = proximityDeviceAuth
    }
}

/// ISO 18013-5 §9.1.3.5 device authentication forms.
public enum ProximityDeviceAuth: Sendable {
    /// `deviceSignature` — an ECDSA signature any third party can verify.
    case signature

    /// `deviceMac` — an HMAC only this reader can check, since the key comes from a DeviceKey/EReaderKey
    /// ECDH. Non-transferable: the reader cannot prove to anyone else that the mdoc answered.
    case mac
}

/// Trust anchors as DER — the facade builds trust validators internally per port.
public struct TrustConfig {
    public let issuerAnchorsDer: [[UInt8]]
    public let readerAnchorsDer: [[UInt8]]
    public init(issuerAnchorsDer: [[UInt8]] = [], readerAnchorsDer: [[UInt8]] = []) {
        self.issuerAnchorsDer = issuerAnchorsDer
        self.readerAnchorsDer = readerAnchorsDer
    }
}
