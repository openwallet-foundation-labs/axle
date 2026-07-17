# EUDI Wallet SDK — Apple adapters

Apple platform adapters that plug the Swift SDK's ports into real device facilities:

| Module | Provides |
|---|---|
| `AppleCore` | Secure Enclave `SecureArea`, keychain storage, URLSession transport, trusted-list bootstrap (`AppleTrust`) |
| `AppleProximity` | ISO 18013-5 BLE transports, QR engagement, reader-side helpers (`MdocReaderRequests`) |
| `AppleDcApi` | IdentityDocumentServices DC-API provider glue (request parsing, reader-trust cache) |
| `AppleAttestation` | App Attest integrity-token provider for the Wallet Provider backend |

## Development notes

### Build & verify

- **This package does not build on Linux** — it imports Apple frameworks. Verify every change by
  building the demo app in Xcode (`../demo-ios`). On a Linux checkout, SourceKit reports
  `No such module 'CborCose'/'SwiftUI'/…` for these sources — that is environment noise, **not** a
  signal the code is broken; but it also means nothing here is compile-checked until Xcode runs.

### Platform constraints (learned the hard way)

- **NFC handover is off the table for the iOS holder.** Apple's NFC/HCE entitlement excludes mDL and
  is EEA-only — holder proximity is **QR + BLE only**. Don't build NFC engagement paths for iOS.
- **DC API requests are entitlement-gated per doctype.** iOS only routes a Digital Credentials request
  to the wallet if the doctype appears in the app's
  `com.apple.developer.identity-document-services.document-provider.mobile-document-types`
  entitlement. **Adding a credential type end-to-end requires updating
  `demo-ios/AxleWallet/AxleWallet/AxleWallet.entitlements`** — and the provisioning profile must
  actually carry the entitlement, or requests silently never arrive.
- **The DC-API provider extension is a separate process.** It cannot fetch trust anchors on demand —
  `AppleTrust` resolves them at app boot and `DcApiReaderTrust` caches the reader anchors for the
  extension; credentials/keys are shared via the keychain access group. If the extension shows
  "Unverified" requesters, check the cached anchors before suspecting the chain.
- **Trust anchors are cached on disk with a 24 h TTL** (`AppleTrust`). After re-anchoring a sandbox
  trusted list, reinstall the app or wait out the TTL — stale anchors mimic a broken chain.
