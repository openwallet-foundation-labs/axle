---
title: iOS adapters & demo
---

# iOS adapters & demo app

The repository ships a **debug wallet** under `demo-ios/` (SwiftUI, *Axle Wallet*) plus a set of
**reusable iOS platform-adapter modules** under `ios/` that implement the SDK's ports. Your app depends on
the `ios/` package instead of copying demo code. `demo-ios/` mirrors the Android `demo/` 1:1.

## The `ios/` adapter package

A single SwiftPM package (`EudiWalletApple`) with four products — the iOS twins of the `android/` modules:

| Product | Provides | Key types |
|---|---|---|
| `AppleCore` | Tier-1 ports | `SecureEnclaveSecureArea` (`SecureArea`, P-256 Secure Enclave), `KeychainStorageDriver` (`StorageDriver`), `URLSessionTransport` (`HttpTransport`), `FileTransactionLogStore` (`TransactionLogStore`), `OSLogWalletLogger`, `AppleTrust` (trusted-list anchors) |
| `AppleProximity` | ISO 18013-5 transports | `BlePeripheralTransport` / `BleCentralTransport` (`ProximityTransport`, both BLE modes, holder + reader) |
| `AppleDcApi` | Digital Credentials API | `DcApiRegistrar` (registration), `DcApiResponder` (response build), `DcApiReaderTrust` (reader badge) |
| `AppleAttestation` | Wallet Provider link | `WalletProviderAttestation` (`WalletAttestationProvider`), `AppAttestIntegrityTokenProvider` (App Attest, with a dev fallback) |

Per-module detail is on the [iOS adapter modules](./guides/ios-adapters) page.

## Assembling a `Wallet`

Everything is host-injected through `WalletPorts` — no DI framework. The demo's
[`DemoWallet.swift`](https://github.com/hopae-official/eudi-wallet-sdk/blob/main/demo-ios/AxleWallet/AxleWallet/DemoWallet.swift)
is the canonical assembly; `boot()` is `async` because it fetches trust anchors before building:

```swift
let secureArea = SecureEnclaveSecureArea(accessGroup: AppleSharedGroups.keychainAccessGroup)
let storage    = KeychainStorageDriver(accessGroup: AppleSharedGroups.keychainAccessGroup)
let http       = URLSessionTransport()
let trust      = await AppleTrust.resolve(http: http, cacheDir: cacheDir)   // JAdES trusted lists → anchors

let wallet = Wallet.create(
  config: WalletConfig(
    issuance: IssuanceConfig(clientId: "wallet-dev", redirectUri: "eu.europa.ec.euidi://authorization"),
    trust: TrustConfig(issuerAnchorsDer: trust.issuer, readerAnchorsDer: trust.reader,
                       registrarAnchorsDer: trust.registrar),
    readerAuth: ReaderAuthLoader.load()),                                    // Read-mDL reader auth (optional)
  ports: WalletPorts(
    secureAreas: [secureArea],                                              // AppleCore — hardware keys
    storage: storage,                                                       // AppleCore
    http: http,                                                             // AppleCore
    walletAttestation: walletAttestation,                                   // AppleAttestation (optional)
    logger: OSLogWalletLogger(),
    transactionLogStore: FileTransactionLogStore()))                        // AppleCore — App Group NDJSON
```

**Port coverage.** The `ios/` package covers every **required** port (`SecureArea`, `StorageDriver`,
`HttpTransport`) plus `TransactionLogStore`, the BLE proximity transports, and `WalletAttestationProvider`.
`WalletClock` / `Rng` use the SDK defaults. The shared **keychain access group** is passed to the secure
area and storage so the DC API extension can read credentials and sign device keys — see below.

## Wallet Provider attestation

`AppleAttestation` implements `WalletAttestationProvider` against a `wallet-provider/` backend: a WUA for
attestation-based client authentication and per-issuance key attestation, with the device attested by
**App Attest** (falling back to a dev token on the Simulator). Wire it only if your deployment needs it —
issuance against issuers that accept a public `client_id` works without it.

```swift
let walletAttestation = WalletProviderAttestation(
  baseUrl: "https://your-wallet-provider.example/wp",
  http: http, secureArea: secureArea,                 // signs the instance-key proof of possession
  integrity: AppAttestIntegrityTokenProvider(),       // App Attest; dev fallback on Simulator
  clientId: "wallet-dev",                             // must equal IssuanceConfig.clientId
  storage: storage)                                   // persists the instance id across restarts
```

The backend verifies the token per-platform (Play Integrity for Android, App Attest for iOS); the adapter
sends `platform: "ios"` so it routes to the App Attest verifier.

## Proximity (BLE)

Build a transport and hand it to the facade. Both BLE modes (peripheral-server and central-client) and both
roles are implemented and phone-to-phone verified against the Android demo:

```swift
// Holder over BLE peripheral-server — present via QR engagement:
let transport = BlePeripheralTransport.holder(logger: log)
try await transport.start()
let session = wallet.proximity.present(transport)

// Reader — scan the QR, then read:
let documents = try await wallet.reader.read(BleCentralTransport.reader(engagement: engagement), ...)
```

See `demo-ios/AxleWallet/AxleWallet/ProximityHolderView.swift` / `ReaderView.swift` for the full lifecycle,
and the [Proximity guide](./guides/proximity).

## Digital Credentials API

iOS exposes the wallet to browser DC API requests through a **provider app extension**
(`AxleWalletIDProvider`), not an in-process activity. The app registers documents on every credential
change:

```swift
if #available(iOS 26.0, *) { await DcApiRegistrar.sync(wallet: wallet) }
```

The extension (`@main IdentityDocumentProvider` + a SwiftUI consent view) answers requests, signing with
the shared Secure Enclave keys. iOS routes only `org-iso-mdoc`. This is meaningfully different from Android
(ExtensionKit extension, shared containers, two-phase request, no matcher) — the full walkthrough is the
**[Digital Credentials API — iOS](./guides/dc-api-ios)** guide.

## Build

Open the Xcode project and run on device — the local SwiftPM packages (`swift/` core + `ios/` adapters) are
referenced by relative path, so there is nothing to fetch:

```bash
open demo-ios/AxleWallet/AxleWallet.xcodeproj
# select an iOS 26 device, Run (⌘R)
```

Toolchain: Xcode 26+, iOS 26 deployment target, a real device (the Secure Enclave, App Attest, App Group
sharing, and the DC API extension need hardware). The DC API doctype capability is an Apple-approved
special entitlement — see the [DC API — iOS](./guides/dc-api-ios#1-entitlements--capabilities) guide.
