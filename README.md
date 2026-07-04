# EUDI Wallet SDK

Headless wallet SDK for the eIDAS 2.0 / EUDI ecosystem. Native Kotlin + Swift with a shared API
contract, ports & adapters architecture, and a Linux-testable core.

- [PLAN.md](PLAN.md) — master plan: architecture, roadmap (M0–M7), spec anchors
- [API-CONTRACT.md](API-CONTRACT.md) — cross-platform API contract (facade, sessions, ports, errors)
- `kotlin/` — Kotlin core modules, pure JVM (`cd kotlin && ./gradlew test`)
- `swift/` — Swift core package, no Apple-framework imports (`cd swift && swift test`)
- `vectors/` — shared golden test vectors consumed by both test suites

Core rule: everything under `kotlin/` and `swift/` builds and tests on plain Linux.
Platform features (secure hardware, storage, BLE, DC API) live behind ports — see the contract §7.

### Linux note (swiftly toolchains)

If BoringSSL (swift-crypto) fails with `'memory' file not found` or `cannot find -lstdc++`,
your clang is probing a GCC dir without libstdc++-dev. Point it at the one that has it, e.g.:

```sh
swift test -Xcc --gcc-install-dir=/usr/lib/gcc/x86_64-linux-gnu/11 \
           -Xcxx --gcc-install-dir=/usr/lib/gcc/x86_64-linux-gnu/11 \
           -Xlinker -L/usr/lib/gcc/x86_64-linux-gnu/11
```

CI container images (`swift:6.x`) are unaffected.
