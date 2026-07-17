# EUDI Wallet SDK — Android adapters

Android platform adapters that plug the Kotlin SDK's ports into real device facilities:

| Module | Provides |
|---|---|
| `core` | Android Keystore `SecureArea` (incl. key attestation), storage, platform glue |
| `proximity` | ISO 18013-5 BLE transports (GATT server/central), QR/NFC engagement |
| `dcapi` | W3C Digital Credentials API provider (CredentialManager registry + request handling) |
| `attestation` | Play Integrity token provider for the Wallet Provider backend |

Adapters depend on SDK **ports** (e.g. `WalletLogger`), never on demo-app types.

## Development notes

### Build & test

- **Not standalone-buildable.** `android/` does not `includeBuild("../kotlin")` itself — it relies on
  the demo's composite build to resolve `com.hopae.eudi:*`. Build it through the demo:
  `cd ../demo && ./gradlew :app:assembleDebug`.
- **`local.properties` is required and gitignored** — create `android/local.properties` (and
  `demo/local.properties`) with `sdk.dir=<your Android SDK>` on every machine. Missing file →
  `SDK location not found`.
- **First build needs network** to fetch the `com.android.library` plugin marker; after that
  `--offline` works.
- **Instrumented (device) tests** — e.g. Android Keystore key attestation:
  `cd ../demo && ./gradlew :android:core:connectedDebugAndroidTest` (device attached via adb).

### Gotchas

- **Play Integrity only passes for the release-signed, Play-distributed package.** Sideloaded debug
  builds yield `UNRECOGNIZED_VERSION` — the Wallet Provider's verdict handling (and its dev bypass)
  exists for exactly this; don't chase it as a device problem.
- **DC API registration is credential-driven** — `dcapi/DcApiRegistrar` registers whatever doctypes
  are in the store. Unlike iOS there is no per-doctype entitlement, so new credential types appear
  automatically once stored.
