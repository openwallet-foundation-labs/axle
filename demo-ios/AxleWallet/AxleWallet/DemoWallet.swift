import AppleAttestation
import AppleCore
import AppleDcApi
import Foundation
import MDoc // ReaderAuthSigner (WalletConfig.readerAuth)
import Wallet

/// Assembles the EUDI Wallet SDK on iOS — the iOS counterpart of android `DemoWallet`.
///
/// Ports are the real Apple-platform adapters: keys in the Secure Enclave, credentials in the shared keychain
/// group, activity in the App Group container. On first `boot()` the wallet also pulls its CA anchors from the
/// sandbox JAdES trusted lists (so it can verify issuers / verifiers / the registrar) and wires the Wallet
/// Provider backend (WUA client-auth + per-issuance key attestation) — both do network, so `boot()` is async
/// and `shared` is only valid after it completes (the app shows a splash until then).
enum DemoWallet {
    private static var built: Wallet?

    /// Valid only after `boot()`. The app gates the wallet UI on `boot()` completing (see `RootView`), so
    /// every access here is post-boot; non-optional so views can keep `let wallet = DemoWallet.shared`.
    static var shared: Wallet { built! }

    /// Held so a wallet reset can wipe persisted activity (`WalletModel.reset`).
    static let txStore = FileTransactionLogStore()

    // Shared across the wallet ports and the attestation provider (same secure area / storage / transport). The
    // Secure Enclave keys + keychain blobs are created under the shared keychain access group so the DC API
    // provider extension (a separate process) can read the credentials and sign with their device keys.
    private static let secureArea = SecureEnclaveSecureArea(accessGroup: AppleSharedGroups.keychainAccessGroup)
    private static let storage = KeychainStorageDriver(accessGroup: AppleSharedGroups.keychainAccessGroup)
    private static let http = URLSessionTransport()

    private static let clientId = "wallet-dev"
    private static let walletProviderBase = "https://dev.api.hopae.com/wp"

    private static var booted = false

    /// Builds the wallet once (fetching trust anchors + wiring attestation). Idempotent; call before using `shared`.
    static func boot() async {
        guard !booted else { return }

        let trust = await AppleTrust.resolve(
            http: http,
            cacheDir: cacheDirectory().appendingPathComponent("trust"),
            log: { message in Task { @MainActor in LogStore.shared.log(message) } }
        )
        // Share the reader anchors with the DC API provider extension (a separate, offline process) so its consent
        // screen can mark a requester verified (reader authentication chained to a trusted reader anchor).
        DcApiReaderTrust.cache(readerAnchorsDer: trust.reader)

        // Wallet Provider backend: the client-auth WUA (attestation-based client auth) and the per-issuance key
        // attestation the local issuer requires. App Attest proves a genuine instance of our app at registration
        // (the backend's IosVerifier verifies the attestation); it falls back to the dev integrity token on the
        // Simulator or if App Attest is unavailable.
        let walletAttestation = WalletProviderAttestation(
            baseUrl: walletProviderBase,
            http: http,
            secureArea: secureArea,
            integrity: AppAttestIntegrityTokenProvider(),
            clientId: clientId,
            storage: storage
        )

        built = Wallet.create(
            config: WalletConfig(
                issuance: IssuanceConfig(clientId: clientId, redirectUri: "eu.europa.ec.euidi://authorization"),
                trust: TrustConfig(
                    issuerAnchorsDer: trust.issuer,
                    readerAnchorsDer: trust.reader,
                    registrarAnchorsDer: trust.registrar
                ),
                transactionLog: TransactionLogConfig(recordFailures: true),
                // Read-mDL reader-auth identity (WRPAC) — the app signs its proximity requests so the other wallet
                // can show us as a verified reader. Loaded from a gitignored bundle asset; nil when absent.
                readerAuth: ReaderAuthLoader.load()
            ),
            ports: WalletPorts(
                secureAreas: [secureArea],
                storage: storage,
                http: http,
                walletAttestation: walletAttestation,
                logger: LogStoreLogger(),
                transactionLogStore: txStore
            )
        )
        booted = true
        LogStore.shared.log("Wallet assembled — trust anchors: \(trust.summary)")
    }

    private static func cacheDirectory() -> URL {
        let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        try? FileManager.default.createDirectory(at: base, withIntermediateDirectories: true)
        return base
    }
}
