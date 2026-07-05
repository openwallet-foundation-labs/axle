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
    public init() {}
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
