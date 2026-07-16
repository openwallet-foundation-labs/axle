---
sidebar_position: 2
title: Architecture
---

# Architecture

## Ports & adapters

The SDK core is pure logic with **no platform dependencies** — it runs and is unit-tested on plain
JVM/Linux (and Linux Swift). Everything platform-specific is a **port** the host implements and
injects at construction time.

```
┌────────────────────────────── your app (UI) ──────────────────────────────┐
│                                                                           │
│ Wallet.create(config, ports)                                              │
│      │                                                                    │
│      ▼                                                                    │
│   ┌────────────────────────── Wallet facade ───────────────────────────┐  │
│   │ credentials · issuance · presentation · proximity                  │  │
│   │ reader · transactions                                              │  │
│   └────────────────────────────────────────────────────────────────────┘  │
│ core modules (pure):  cbor · sdjwt · mdoc · openid4vci ·                  │
│    openid4vp · trust · statuslist · credential-store ·                    │
│    proximity · txlog                                                      │
│                                                                           │
│ ports you inject ▸ SecureArea · StorageDriver ·                           │
│    HttpTransport · WalletClock · Rng · WalletLogger ·                     │
│    TransactionLogStore · WalletAttestationProvider                        │
│                                                                           │
│ per-session port ▸ ProximityTransport  (present / read)                   │
└───────────────────────────────────────────────────────────────────────────┘
```

## The ports

The full SPI lives in the `wallet-api` module (Kotlin `com.hopae.eudi.wallet.spi`, Swift `WalletAPI`).
`WalletPorts` bundles them; three are **required** and the rest carry defaults.

| Port                        | Required | Responsibility                                | Typical adapter                                            |
| --------------------------- | :------: | --------------------------------------------- | ---------------------------------------------------------- |
| `SecureArea`                |   yes    | Create keys, sign, key-agree, attest, delete  | Android Keystore / iOS Secure Enclave (software for tests) |
| `StorageDriver`             |   yes    | Persist bytes by collection/key, with a tx    | Encrypted file / DataStore / Keychain                      |
| `HttpTransport`             |   yes    | Execute HTTP, honouring `followRedirects`     | OkHttp / URLSession                                        |
| `WalletClock`               |    no    | Current time (default: system clock)          | `WalletClock.System` / `SystemClock`                       |
| `Rng`                       |    no    | Random bytes (default: platform secure RNG)   | `Rng.Default` / `SystemRng`                                |
| `WalletLogger`              |    no    | Structured log sink (default: none)           | App-specific (logcat / os_log / file)                      |
| `TransactionLogStore`       |    no    | Append-only audit persistence                 | Encrypted store (in-memory default)                        |
| `WalletAttestationProvider` |    no    | Wallet Provider link (WUA + key attestation)  | Backend client                                             |

`SecureArea` is the crypto boundary: **every** operation that touches a private key (`sign`,
`keyAgreement`, `attestation`) goes through it, while public-key verification, hashing, and encoding
stay in the pure core and run anywhere (including Linux CI). `secureAreas` is a **list** — the first is
the default; extras let one wallet span, say, a StrongBox area and a TEE area.

`ProximityTransport` is a **per-session** port, not a `WalletPorts` field: you pass a fresh one to each
`wallet.proximity.present(transport)` / `wallet.reader.read(transport, …)` call, because a BLE/NFC
channel is bound to a single in-person exchange.

The SDK **owns** credential, key, issuance, and presentation lifecycle. The host only supplies the
thin capabilities above — there is no DI framework, just constructor injection through
`Wallet.create(config, ports)`.

## Adapters → SPI

The `android/` modules are ready-made adapters (Maven group **`com.hopae.eudi.android`**, distinct from
the SDK's `com.hopae.eudi` so artifacts never clash). Depend on them directly, or read them as a
reference implementation for your own platform:

| Adapter (`android/`)          | Implements                  | Module        |
| ----------------------------- | --------------------------- | ------------- |
| `AndroidKeystoreSecureArea`   | `SecureArea`                | `core`        |
| `FileStorageDriver`           | `StorageDriver`             | `core`        |
| `OkHttpTransport`             | `HttpTransport`             | `core`        |
| `FileTransactionLogStore`     | `TransactionLogStore`       | `core`        |
| `BleGattServerTransport` / `BleGattClientTransport` | `ProximityTransport` | `proximity` |
| `WalletProviderAttestation`   | `WalletAttestationProvider` | `attestation` |

`WalletClock` / `Rng` use the SDK defaults; `WalletLogger` is intentionally app-supplied (real logging
is app-specific).

The `ios/` package (SwiftPM `EudiWalletApple`) is the 1:1 twin, implementing the same ports against Apple
frameworks:

| Adapter (`ios/`)                                  | Implements                  | Module           |
| ------------------------------------------------- | --------------------------- | ---------------- |
| `SecureEnclaveSecureArea`                         | `SecureArea`                | `AppleCore`      |
| `KeychainStorageDriver`                           | `StorageDriver`             | `AppleCore`      |
| `URLSessionTransport`                             | `HttpTransport`             | `AppleCore`      |
| `FileTransactionLogStore`                         | `TransactionLogStore`       | `AppleCore`      |
| `BlePeripheralTransport` / `BleCentralTransport`  | `ProximityTransport`        | `AppleProximity` |
| `WalletProviderAttestation`                       | `WalletAttestationProvider` | `AppleAttestation` |

**Rolling your own.** An adapter qualifies by passing the shared **contract test suites** shipped in the
test kit (`SecureAreaContract.verify(area)`, `StorageDriverContract.verify(driver)`) — the same checks
run on Linux CI against `SoftwareSecureArea` / `InMemoryStorageDriver` and in the device lab against the
real adapters. See [Getting started](./getting-started#your-own-adapters).

**Presets vs. demo.** `android/` and `ios/` are the reusable adapter layers your app ships against;
`demo/` (Jetpack Compose) and `demo-ios/` (SwiftUI, *Axle Wallet*) are full debug wallets that assemble
those adapters end to end — see [Android adapters & demo](./android-demo) and
[iOS adapters & demo](./ios-demo).

## Modules

Each concern is a separate module so it can be tested in isolation and reused:

`cbor` (CBOR/COSE) · `sdjwt` (SD-JWT VC, JOSE) · `mdoc` (ISO 18013-5) · `openid4vci` · `openid4vp` ·
`trust` (X.509 PKIX) · `statuslist` (Token Status List) · `credential-store` · `proximity`
(18013-5 session) · `txlog` (audit) · `wallet` (the facade that assembles them).

Your app compiles against exactly two modules: **`wallet`** (the facade — `Wallet`, the six services,
`WalletConfig`, `WalletPorts`) and **`wallet-api`** (the SPI you implement). The concern modules above
are internal wiring — `Wallet.create` builds them for you, and you never reference them directly.

## Lifecycle & threading

`Wallet` is **multi-instance** and **thread-safe**: share one instance across coroutines / tasks, or
run several independent wallets in one process — there is no global state.

`Wallet.create` opens a `CoroutineScope(SupervisorJob() + Dispatchers.Default)` that owns every
in-flight issuance, presentation, and proximity session. `Wallet` is `AutoCloseable`; `close()` cancels
that scope (tearing down any running sessions) and is **idempotent** — safe to call on logout or
teardown, and a no-op afterwards. Because the scope uses a `SupervisorJob`, one failed session never
cancels its siblings. An individual in-flight session can also be stopped on its own with
`session.cancel()`.

## Sessions as state machines

Issuance, presentation, and proximity are **suspending state machines**. The flow pauses at
interaction points (browser authorization, `tx_code`, consent) and resumes when the app calls back —
a `StateFlow` in Kotlin, an `AsyncStream` in Swift.

```
start(...) → Processing → [pause: AuthorizationRequired / TxCodeRequired / RequestResolved]
           → [app resumes] → Submitting → Completed | Failed | Declined
```
