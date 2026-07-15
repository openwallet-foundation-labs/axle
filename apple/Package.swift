// swift-tools-version: 5.10
import PackageDescription

// Apple platform adapters for the EUDI Wallet SDK — the iOS counterpart of `../android`.
// Depends on the platform-neutral core `../swift` (= `../kotlin`) and implements its SPI ports
// (SecureArea, StorageDriver, HttpTransport, …) against Apple frameworks. Kept as a SEPARATE
// package so the core's Linux CI never sees Security/CoreBluetooth/IdentityDocumentServices.
let package = Package(
    name: "EudiWalletApple",
    platforms: [.iOS("26.0")],
    products: [
        // Mirrors android/core: SecureArea, StorageDriver, TransactionLogStore, HttpTransport, WalletLogger.
        .library(name: "AppleCore", targets: ["AppleCore"]),
    ],
    dependencies: [
        .package(path: "../swift"),
    ],
    targets: [
        .target(
            name: "AppleCore",
            dependencies: [
                .product(name: "WalletAPI", package: "swift"),
            ]
        ),
    ]
)
