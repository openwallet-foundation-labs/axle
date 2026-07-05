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
   ┌──────────────────────────── your app (UI) ─────────────────────────────┐
   │                                                                        │
   │   Wallet.create(config, ports)                                         │
   │        │                                                               │
   │        ▼                                                               │
   │   ┌────────────────── Wallet facade ──────────────────┐                │
   │   │ credentials · issuance · presentation · proximity │                │
   │   └───────────────────────┬───────────────────────────┘                │
   │        core modules (pure)│  cbor · sdjwt · mdoc · openid4vci/vp ·     │
   │                           │  trust · statuslist · credential-store ·   │
   │                           │  proximity · txlog                         │
   │                           ▼                                            │
   │   ports (you inject) ▸ SecureArea · StorageDriver · HttpTransport ·    │
   │                        Rng · WalletClock · ProximityTransport ·        │
   │                        TransactionLogStore · WalletAttestationProvider │
   └────────────────────────────────────────────────────────────────────────┘
```

## The ports

| Port                        | Responsibility                      | Typical adapter                                            |
| --------------------------- | ----------------------------------- | ---------------------------------------------------------- |
| `SecureArea`                | Create keys, sign, hold public keys | Android Keystore / iOS Secure Enclave (software for tests) |
| `StorageDriver`             | Persist bytes by collection/key     | Encrypted file / DataStore / Keychain                      |
| `HttpTransport`             | Execute HTTP with redirect control  | OkHttp / URLSession                                        |
| `Rng`                       | Random bytes                        | `SecureRandom` (a default is provided)                     |
| `WalletClock`               | Current time                        | System clock (a default is provided)                       |
| `ProximityTransport`        | BLE/NFC duplex channel              | GATT peripheral (in-person only)                           |
| `TransactionLogStore`       | Append-only audit persistence       | Encrypted store (in-memory default)                        |
| `WalletAttestationProvider` | Wallet Provider link (WUA)          | Backend client                                             |

The SDK **owns** credential, key, issuance, and presentation lifecycle. The host only supplies the
thin capabilities above — there is no DI framework, just constructor injection.

## Modules

Each concern is a separate module so it can be tested in isolation and reused:

`cbor` (CBOR/COSE) · `sdjwt` (SD-JWT VC, JOSE) · `mdoc` (ISO 18013-5) · `openid4vci` · `openid4vp` ·
`trust` (X.509 PKIX) · `statuslist` (Token Status List) · `credential-store` · `proximity`
(18013-5 session) · `txlog` (audit) · `wallet` (the facade that assembles them).

## Sessions as state machines

Issuance, presentation, and proximity are **suspending state machines**. The flow pauses at
interaction points (browser authorization, `tx_code`, consent) and resumes when the app calls back —
a `StateFlow` in Kotlin, an `AsyncStream` in Swift.

```
start(...) → Processing → [pause: AuthorizationRequired / TxCodeRequired / RequestResolved]
           → [app resumes] → Submitting → Completed | Failed | Declined
```
