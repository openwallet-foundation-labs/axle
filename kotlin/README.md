# EUDI Wallet SDK — Kotlin

The platform-neutral Kotlin SDK (plain JVM Gradle build): credential store, OpenID4VCI/VP, mdoc
(ISO 18013-5), SD-JWT VC, trust/X.509, status lists, proximity engine. Doctype-agnostic by design —
adding a new credential type needs **no SDK change** (matching, storage, selective disclosure and
presentation all key off the `docType`/`vct` carried by the credential). Android adapters live in
[`../android`](../android); the demo app in [`../demo`](../demo).

## Development notes

### Build & test

```bash
cd kotlin
./gradlew build      # plain JVM — no Android SDK required
```

- The demo consumes this build via a Gradle **composite build** (`demo/settings.gradle.kts`
  `includeBuild("../kotlin")`) — no publishing step; demo builds always track local SDK source.
- **Live E2E** (issue → hold → present → verify against the deployed sandbox):
  `EUDI_E2E=1 ./gradlew :wallet:test --tests '*FullEcosystemE2eTest*' -DEUDI_E2E=1`.

### Cross-stack gotchas

- **X.509 here is Java PKIX — more lenient than swift-certificates.** Java treats `extendedKeyUsage`
  as a known extension, so a chain with a *critical* EKU (required by ISO 18013-5 on mDL Document
  Signers) validates here while the Swift SDK rejected it until it grew an explicit EKU policy.
  **Green Kotlin tests do not prove the Swift stack passes** — for changes to trust/verification or
  the sandbox certificate profiles, also run the Swift fixture harness
  (see `swift/README.md`, `LiveIssuerFixtureTests`).
- The Swift SDK is a 1:1 port of this one (module-for-module, test-for-test). When you change
  verification behaviour here, port the change and its tests across in the same PR.
