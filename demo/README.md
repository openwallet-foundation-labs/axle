# EUDI Wallet SDK — Android Demo

A minimal **debug wallet** app that drives the SDK on Android through Jetpack Compose. It exists to
exercise the public facade (`Wallet`) with real Android adapters, not to be a production wallet.

## What it shows

| Tab | Flow | SDK entry point |
|-----|------|-----------------|
| **Credentials** | List stored credentials + parsed claims | `wallet.credentials.list()` |
| **Issue** | Paste a credential-offer URI → OpenID4VCI issuance (pre-authorized + `tx_code`) | `wallet.issuance.resolveOffer` / `start` |
| **Present** | Paste a verifier request (`openid4vp://…`) → resolve → consent → submit | `wallet.presentation.start` |

## How the SDK is wired (`DemoWallet.kt`)

The app injects thin platform adapters into `WalletPorts`:

- **SecureArea** → `SoftwareSecureArea` (testkit) — *debug only*; holder keys live in memory and do not
  survive a process restart. A production wallet injects an **Android Keystore**-backed `SecureArea`.
- **StorageDriver** → `FileStorageDriver` — persists credentials under the app's private files dir
  (`adapters/FileStorageDriver.kt`). Production should encrypt at rest.
- **HttpTransport** → `OkHttpTransport` — OkHttp, honouring the per-request redirect policy
  (`adapters/OkHttpTransport.kt`).

That is the whole integration surface — the SDK owns credential/key/issuance/presentation lifecycle;
the app only supplies these ports.

## Build

The demo is a **separate Gradle project** that consumes the SDK as a
[composite build](https://docs.gradle.org/current/userguide/composite_builds.html)
(`includeBuild("../kotlin")`), so it always tracks local SDK source with no publishing step. It does
**not** participate in the SDK's own Linux build, so the SDK stays buildable without an Android SDK.

```bash
cd demo
# point at your Android SDK (already in local.properties: sdk.dir=/home/unknown/android-sdk)
./gradlew :app:assembleDebug
# → app/build/outputs/apk/debug/app-debug.apk
```

Toolchain: AGP 9.2.1, Gradle 9.5, `compileSdk` 36, `minSdk` 29.

## Try it

1. `adb install -r app/build/outputs/apk/debug/app-debug.apk`
2. **Issue** — paste a pre-authorized credential offer (e.g. from the EUDI test issuer at
   `https://issuer.eudiw.dev`) and its `tx_code`, tap **Issue**.
3. **Credentials** — pull **Refresh**; the new credential and its disclosed claims appear.
4. **Present** — paste a verifier `openid4vp://` request, **Resolve** to see the verifier + whether it
   is trusted, then **Present (auto-select)**.

## Proximity (ISO 18013-5)

The SDK's proximity engine (engagement, ECDH session, DeviceRequest → DeviceResponse, reader
authentication) is complete and unit-tested. Presenting to an in-person reader additionally needs a
**BLE `ProximityTransport`** adapter (a GATT peripheral) — that is device-only integration and is not
included here. See the developer docs for a BLE transport guide.

## Development notes

- **App identity vs code namespace** — the `applicationId` is `com.hopae.axle.wallet` (label
  "Axle Wallet") but the code package stays `com.hopae.eudi.demo`. Use the *application id* for
  `adb pm/am/uninstall/logcat --pid`; use the code package when grepping sources.
- **Logs**: `adb logcat -s EudiDemo`.
- **Image claims render by element name.** The SDK exposes mdoc bstr values as base64url text
  (`CborJson` — by design, for DCQL matching); `ui/ClaimImage.kt` detects
  `portrait`/`enrolment_portrait_image`/`signature_usual_mark` by name and renders thumbnail rows on
  every claim surface (detail, consents, proximity, reader). New image-bearing elements go in that
  one list — and in the iOS mirror (`demo-ios` `CredentialContent.swift`).
- **Presenting is request-driven by design.** The document detail page deliberately has no
  proximity/present button; holder sharing starts from Home, and the reader screen requests **one
  document kind at a time** (`ReaderDocKind` / `readerRequest(kind)` in `ui/ProximityScreens.kt`).
- **This UI is mirrored 1:1 by `demo-ios`** — when changing `CredentialVisuals`, `CredentialContent`,
  or screen flows, port the change in the same PR.
