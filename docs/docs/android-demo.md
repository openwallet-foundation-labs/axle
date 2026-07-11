---
title: Android adapters & demo
---

# Android adapters & demo app

The repository ships a **debug wallet** under `demo/` (Jetpack Compose) plus a set of **reusable Android
platform-adapter libraries** under `android/` that implement the SDK's ports. Your app depends on the
`android/` libraries instead of copying demo code.

## The `android/` adapter libraries

Three modules under the Maven group **`com.hopae.eudi.android`** (distinct from the SDK's
`com.hopae.eudi`, so artifacts never clash):

| Module | Provides | Key classes |
|---|---|---|
| `core` | Tier-1 ports | `AndroidKeystoreSecureArea` (`SecureArea`, hardware-backed), `FileStorageDriver` (`StorageDriver`), `OkHttpTransport` (`HttpTransport`), `FileTransactionLogStore` (`TransactionLogStore`) |
| `proximity` | ISO 18013-5 transports | `BleGattClientTransport` / `BleGattServerTransport` (`ProximityTransport`), `NfcEngagementService` (holder HCE), `NfcReader` (reader). Its **library manifest** merges the BLE/NFC permissions + the HCE service into your app |
| `dcapi` | Digital Credentials API | `DcApiRegistrar` (Credential Manager registration + matcher), `DcApiRequest` / `DcApiResult` (envelope + marshalling), `DcApiBranding` (OS-selector logo/branding) |

## Assembling a `Wallet`

Everything is host-injected through `WalletPorts` — no DI framework:

```kotlin
val logger = LogWalletLogger()   // your WalletLogger (the demo routes to logcat + on-screen + file)
val wallet = Wallet.create(
    config = WalletConfig(),
    ports = WalletPorts(
        secureAreas = listOf(AndroidKeystoreSecureArea()),                       // android/core — hardware keys
        storage = FileStorageDriver(File(filesDir, "wallet")),                   // android/core
        http = OkHttpTransport(logger = logger),                                 // android/core
        transactionLogStore = FileTransactionLogStore(File(filesDir, "tx.log")), // android/core
        logger = logger,
        // walletAttestation = ...   // WUA (Wallet Provider) — no adapter yet; see the attestation track
    ),
)
```

**Port coverage.** The `android/` libraries cover every **required** port (`SecureArea`, `StorageDriver`,
`HttpTransport`) plus `TransactionLogStore` and the proximity transports. `WalletClock` / `Rng` use the
SDK defaults (`WalletClock.System` / `Rng.Default`). `WalletLogger` is intentionally **app-supplied** —
real logging (screen/file) is app-specific, so no concrete logger ships in `android/core`. The one port
with **no adapter yet** is `WalletAttestationProvider` (Wallet Unit Attestation), tracked in the
attestation workstream.

## Proximity (BLE + NFC)

Build a transport and hand it to the facade. Both BLE modes and NFC **static + negotiated** handover are
implemented and phone-to-phone device-verified (see `INTEROP.md`).

```kotlin
// Holder over BLE peripheral-server:
val server = BleGattServerTransport(context, uuid, Ble.PERIPHERAL_SERVER, retrievalMethods, logger = logger)
val session = wallet.proximity.present(server)                      // QR engagement

// Reader:
val docs = wallet.reader.read(clientTransport, engagement, requested)
```

For NFC the holder arms the HCE with an `NfcEngagementProcessor` (static, or a negotiated `hr → hs`
selector); the reader drives `NfcReader.readHandover(...)` which auto-detects static vs the TNEP
negotiated dance. See `demo/.../ui/ProximityScreens.kt` for the full lifecycle, and the
[Proximity guide](./guides/proximity).

## Digital Credentials API

```kotlin
DcApiRegistrar.register(activity, wallet, DcApiBranding(logoPng = appIconPng()), logger = logger)
```

Registers the wallet's credentials with the Credential Manager (the OS credential selector), branded with
your app's icon. Handle the routed intent in a thin activity with `DcApiRequest` / `DcApiResult` (see the
demo's `GetCredentialActivity`).

## Build

The demo consumes the SDK **and** the adapters via composite builds
(`includeBuild("../kotlin")` + `includeBuild("../android")`):

```kotlin
// demo/app/build.gradle.kts
implementation("com.hopae.eudi:wallet:0.0.1-SNAPSHOT")
implementation("com.hopae.eudi.android:core:0.0.1-SNAPSHOT")
implementation("com.hopae.eudi.android:proximity:0.0.1-SNAPSHOT")
implementation("com.hopae.eudi.android:dcapi:0.0.1-SNAPSHOT")
```

```bash
cd demo
./gradlew :app:assembleDebug        # → app/build/outputs/apk/debug/app-debug.apk
adb install -r app/build/outputs/apk/debug/app-debug.apk
```

Toolchain: AGP 9.2.1, Gradle 9.5, `compileSdk` 36, `minSdk` 29. The `android/` build needs
`android/local.properties` with `sdk.dir=/path/to/android-sdk`.
