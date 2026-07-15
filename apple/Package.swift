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
        // Mirrors android/proximity: ISO 18013-5 BLE ProximityTransport (peripheral holder + central reader).
        .library(name: "AppleProximity", targets: ["AppleProximity"]),
        // Mirrors android/attestation: App Attest integrity token + WalletProviderAttestation (WUA + key attestation).
        .library(name: "AppleAttestation", targets: ["AppleAttestation"]),
        // Mirrors android/dcapi: registers mdoc credentials with IdentityDocumentServices + builds DC API responses.
        .library(name: "AppleDcApi", targets: ["AppleDcApi"]),
    ],
    dependencies: [
        .package(path: "../swift"),
    ],
    targets: [
        .target(
            name: "AppleCore",
            dependencies: [
                .product(name: "WalletAPI", package: "swift"),
                // EcPublicKey / EcCurve live in CborCose (the SecureArea port references them).
                .product(name: "CborCose", package: "swift"),
                // FileTransactionLogStore persists entries; re-exported so the app sees the txlog types.
                .product(name: "TransactionLog", package: "swift"),
                // AppleTrust fetches CA anchors from the JAdES trusted lists; re-exported for the app.
                .product(name: "TrustList", package: "swift"),
            ]
        ),
        .target(
            name: "AppleProximity",
            dependencies: [
                // ProximityTransport port + NfcCarrier.
                .product(name: "WalletAPI", package: "swift"),
                // DeviceEngagement.bleRetrievalMethod / parseBle — the ISO 18013-5 BLE engagement helpers.
                .product(name: "Proximity", package: "swift"),
                // RequestedDocument / VerifiedDocument so the reader helpers keep MDoc/Cbor out of the app.
                .product(name: "MDoc", package: "swift"),
                .product(name: "CborCose", package: "swift"),
            ]
        ),
        .target(
            name: "AppleAttestation",
            dependencies: [
                // WalletProviderAttestation + IntegrityTokenProvider (re-exported so the app sees them).
                .product(name: "WalletProvider", package: "swift"),
                .product(name: "WalletAPI", package: "swift"),
            ]
        ),
        .target(
            name: "AppleDcApi",
            dependencies: [
                // Shared App Group / keychain group constants (reader-anchor cache location).
                "AppleCore",
                // The facade the app + extension drive: credentials list/changes + proximity.respondDcApiMdoc.
                .product(name: "Wallet", package: "swift"),
                // Credential / CredentialFormat / CredentialId the registrar reads.
                .product(name: "WalletAPI", package: "swift"),
                // DeviceRequest decode — the consent-consistency check reads the raw request we are about to sign.
                .product(name: "MDoc", package: "swift"),
            ]
            // Imports IdentityDocumentServices (iOS 26); the system framework autolinks from the SDK.
        ),
    ]
)
