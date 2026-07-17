# EUDI Wallet SDK — Swift

The platform-neutral Swift SDK (SPM package): credential store, OpenID4VCI/VP, mdoc (ISO 18013-5),
SD-JWT VC, trust/X.509, status lists, proximity engine. UI-less and Apple-framework-free — it builds
and tests on **Linux and macOS**. Apple-specific adapters (Secure Enclave, BLE, DC API) live in
[`../ios`](../ios); the demo app lives in [`../demo-ios`](../demo-ios).

## Development notes

### Build & test

```bash
swift build
swift test                    # macOS
swift test -Xlinker -L/usr/lib/gcc/x86_64-linux-gnu/11   # Linux (see below)
```

- **Linux link failure in swift-crypto/BoringSSL** — `swift test` fails at link time unless the GCC
  libstdc++ directory is passed: `-Xlinker -L/usr/lib/gcc/x86_64-linux-gnu/11` (adjust to your GCC
  version).
- **IDE "No such module" noise on Linux** — SourceKit cannot resolve Apple-only modules (`SwiftUI`,
  `AppleCore`, …) referenced by sibling packages. `swift build`/`swift test` are the source of truth
  for THIS package; the diagnostics are noise.

### Cross-stack gotchas (symptom → cause → fix)

- **"chain does not validate to a trust anchor: []" only on Swift, while Kotlin/Node accept the same
  chain** → swift-certificates' `Verifier` rejects any chain carrying a *critical* extension that no
  policy declares it handles, and `RFC5280Policy` does not process `extendedKeyUsage`. ISO 18013-5
  Annex B **requires** a critical EKU (id-mdl-kp-mdlDS) on mDL Document Signers, so every
  spec-conformant DS chain failed until `AcceptExtendedKeyUsagePolicy` was composed into
  `Sources/Trust/X509ChainValidator.swift`. **Any new critical extension introduced in the sandbox
  certificate profiles must be re-checked against the Swift validator** — Java PKIX and Node are
  lenient here and will not catch it.
- **MSO `ValidityInfo` tdate parse errors** → `ISO8601DateFormatter([.withInternetDateTime])` rejects
  fractional seconds; `MsoCodec` falls back to a fractional-seconds formatter (`Sources/MDoc/Mdoc.swift`).
  Note our own issuer emits whole-second tdates (the mdoc lib truncates milliseconds, as ISO 18013-5
  requires) — if you hit this, the credential came from a third-party issuer.
- **`Cbor` is not `Sendable`** — a `Sendable` struct holding a `Cbor` value warns today and becomes an
  error under the Swift 6 language mode.

### Fixture-driven interop harness

Issue every `mso_mdoc` credential config through the **real issuer-be code path** and verify it with
the exact stack the iOS wallet runs (`MdocVerifier` + `X5cMdocIssuerTrust` + `X509ChainValidator`):

```bash
cd ecosystem/issuer-be
npx ts-node -T --skipProject --compilerOptions \
  '{"module":"commonjs","moduleResolution":"node","experimentalDecorators":true,"esModuleInterop":true,"target":"ES2022"}' \
  tools/gen-mdoc-fixtures.ts > /tmp/mdoc-fixtures.json
cd ../../swift
EUDI_MDOC_FIXTURES=/tmp/mdoc-fixtures.json swift test --filter LiveIssuerFixtureTests \
  -Xlinker -L/usr/lib/gcc/x86_64-linux-gnu/11
```

Run it whenever you touch `Sources/Trust`, mdoc verification, or the ecosystem certificate profiles —
it is what caught the critical-EKU incident.
