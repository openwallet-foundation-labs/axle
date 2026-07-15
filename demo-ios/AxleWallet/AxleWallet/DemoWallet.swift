import AppleCore
import Foundation
import Wallet
import WalletAPI
import WalletTestKit

/// Phase-1 bootstrap of the EUDI Wallet SDK on iOS — the iOS counterpart of android `DemoWallet.kt`.
///
/// TEMPORARY adapters: `SoftwareSecureArea` + `InMemoryStorageDriver` (from WalletTestKit) exist only
/// to prove `Wallet.create` compiles and runs on-device; they hold nothing across a relaunch. Phase 2
/// replaces them with `SecureEnclaveSecureArea` + a Keychain `StorageDriver`. Only the network adapter
/// (`URLSessionTransport`, from AppleCore) is already production-shaped.
enum DemoWallet {
    static let shared: Wallet = build()

    private static func build() -> Wallet {
        Wallet.create(
            config: WalletConfig(
                issuance: IssuanceConfig(
                    clientId: "wallet-dev",
                    redirectUri: "eu.europa.ec.euidi://authorization"
                )
            ),
            ports: WalletPorts(
                secureAreas: [SoftwareSecureArea()],
                storage: InMemoryStorageDriver(),
                http: URLSessionTransport()
            )
        )
    }
}
