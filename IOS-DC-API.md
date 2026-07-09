# iOS Digital Credentials API — feasibility and plan

Researched 2026-07-09. Question: **can this SDK serve both `openid4vp-v1-*` and `org-iso-mdoc` over the
Digital Credentials API on iOS, the way it already does on Android?**

## Answer

**No — and not because of anything in our code.** Apple's platform routes exactly one DC API protocol
to third-party wallets: `org-iso-mdoc` (ISO/IEC TS 18013-7:2025 Annex C). OpenID4VP over the browser
DC API is unreachable on iOS today.

What *is* reachable, and what we should build, is the `org-iso-mdoc` provider extension. Every
cryptographic and CBOR primitive it needs already exists in our Swift core and is byte-for-byte
identical to what the EUDI reference implementation does. The work is a platform adapter, not
protocol work.

Meanwhile `openid4vp` on iOS is not lost — it is served through the same-device deep link and
cross-device `request_uri` flows we already support (`wallet.presentation.start(requestUri)`). Only
the *browser-mediated* variant is unavailable.

### The platform ceiling, precisely

From Apple's own documentation (iOS/iPadOS 26.0, macOS 26.0):

- `IdentityDocumentServicesUI.IdentityDocumentRequestScene` — **Conforming Types:
  `ISO18013MobileDocumentRequestScene`** (one).
- `IdentityDocumentServices.IdentityDocumentWebPresentmentRequest` (a *closed* protocol) —
  **Conforming Types: `ISO18013MobileDocumentRequest`** (one).

The W3C DC API community reference states it plainly for iOS/iPadOS: "ISO 18013-7 Annex C for
presentation. OpenID for Verifiable Presentations (Annex D) is not supported."

At W3C TPAC (Nov 2025) the FedID WG froze the protocol list to `openid4vp-v1-unsigned`,
`openid4vp-v1-signed`, `openid4vp-v1-multisigned`, `org-iso-mdoc`, and `openid4vci-v1`. Apple has
implemented one of them. There is no public Apple roadmap for the others as of 2026-07.

Alternative browser engines under the EU DMA do not change this: wallet registration goes through the
OS `IdentityDocumentProviderRegistrationStore`, which only models mobile documents.

### Protocol matrix

| Protocol | Android (Credential Manager) | iOS (IdentityDocumentServices) | SDK entry point |
| --- | --- | --- | --- |
| `openid4vp-v1-unsigned` | ✅ shipping | ❌ platform | `wallet.presentation.startDcApi(json, origin)` |
| `openid4vp-v1-signed` | ✅ shipping | ❌ platform | `wallet.presentation.startDcApi(json, origin)` |
| `org-iso-mdoc` | ✅ shipping | ✅ **buildable** | `wallet.proximity.respondDcApiMdoc(deviceRequest, encryptionInfo, origin)` |
| SD-JWT VC over DC API | ✅ (openid4vp) | ❌ mdoc-only registration | — |

The `openid4vp` code paths stay compiled and tested on both platforms. On iOS they simply have no
browser caller until Apple ships a second scene type. If that happens, the adapter grows a branch;
the core does not change.

## What we already have

Verified against the tree at `b82baeb`. The core is complete for `org-iso-mdoc` in **both** languages:

| Piece | Swift | Kotlin |
| --- | --- | --- |
| HPKE base-mode seal (RFC 9180, DHKEM-P256 / HKDF-SHA256 / AES-128-GCM) | `Sources/MDoc/Hpke.swift:29` | `mdoc/…/Hpke.kt:40` |
| Annex C SessionTranscript `[null, null, ["dcapi", SHA-256(CBOR([encInfoB64, origin]))]]` | `Sources/MDoc/MdocSessionTranscript.swift:10` | `mdoc/…/MdocSessionTranscript.kt:14` |
| Holder flow: decode DeviceRequest → match → DeviceResponse → HPKE seal → `["dcapi", {enc, cipherText}]` | `Sources/Wallet/ProximityService.swift:99` | `wallet/…/ProximityService.kt:125` |
| OpenID4VP DC API handover + resolve/respond (Android-only caller) | `Oid4vpSessionTranscript.swift:25`, `Openid4VpClient.swift:49,74` | same |
| Reader auth verification (ISO 18013-5 §9.1.4) against configured anchors | `ProximityService.verifyReader` | same |

Our wire format matches `av-lib-ios-w3c-dc-api` v0.20.1 exactly — same handover, same `info =
CBOR(SessionTranscript)`, same empty `aad`, same `["dcapi", {enc, cipherText}]` envelope, same
`CipherSuite(kem: .P256, kdf: .KDF256, aead: .AESGCM128)`. See `../eudi-ref/ios-dc-api.md` for the
reference teardown.

## What is missing

### P0 — Apple platform adapters (blocks everything else)

The provider extension is a **separate process**. It must open the wallet's keychain and sign with the
credential's device key. Today `swift/Sources` has no Apple `SecureArea` or `StorageDriver` adapter at
all — only `WalletTestKit.SoftwareSecureArea`. We need:

- a Secure Enclave `SecureArea` that creates keys with `kSecAttrAccessGroup` set to a **shared**
  keychain group, otherwise the extension cannot sign with keys the main app created;
- a keychain/App-Group-container `StorageDriver` that both processes can read.

The reference sidesteps the design question by having `DcApiHandler(serviceName:accessGroup:)`
construct `KeyChainStorageService` and register secure areas itself. Our ports model is cleaner: the
extension builds a `Wallet` with the same adapters the app uses, pointed at the shared group.

### P1 — small API impedance mismatches

- `respondDcApiMdoc` returns **base64url `String`**. Apple's `ISO18013MobileDocumentResponse` takes raw
  `Data`. Add a `Data`-returning variant (or have the adapter `Base64Url.decode`). Android wants the
  base64url form, so keep both.
- **Origin normalization.** The reference trims a trailing `/` from `originUrl` before hashing it into
  the handover. `context.requestingWebsiteOrigin?.absoluteString` can carry one. We take `origin`
  verbatim, so a trailing slash silently changes the SessionTranscript hash and the verifier rejects
  the response. Normalize in the SDK, not in each app.
- `Credential` exposes `format.docType` but not the MSO `validUntil`, which registration wants for
  `invalidationDate`. It is optional (the reference passes the document's `validUntil`; we can pass
  `nil` initially), but exposing it is the right fix.

### P2 — the extension itself

Mirror Android's `demo/app/.../DcApiRegistrar.kt` with a Swift `DcApiRegistrar` plus a provider
extension target in the demo:

```swift
@main
struct WalletDocumentProvider: IdentityDocumentProvider {
  var body: some IdentityDocumentRequestScene {
    ISO18013MobileDocumentRequestScene { context in ConsentView(context: context) }
  }
}
```

Registration, on issue and on delete:

```swift
try await IdentityDocumentProviderRegistrationStore().addRegistration(
  MobileDocumentRegistration(
    mobileDocumentType: docType,                     // from CredentialFormat.msoMdoc(docType:)
    supportedAuthorityKeyIdentifiers: [akiFromIssuerAuthChain],
    documentIdentifier: credential.id.value,
    invalidationDate: mso.validUntil))
```

Note there is **no matcher** on iOS — the OS owns matching and the credential picker. That deletes the
whole WASM matcher problem we have on Android.

Ship gate for customers: `com.apple.developer.identity-document-services.document-provider.mobile-document-types`
is an Apple-approved special entitlement, and each servable doctype must be listed in it.

### P3 — where we should beat the reference

Apple's flow is two-phase, and the reference leaves both halves under-defended:

1. **Pre-consent** the extension only has the OS-parsed `context.request`. Its
   `requestAuthentications.first?.authenticationCertificateChain` is enough to run our
   `X509ChainValidator` against the configured reader anchors and show a *verified* requester identity
   on the consent screen. The reference just prints the certificate's subject without validating it.
2. **Post-consent**, inside `context.sendResponse { rawRequest in … }`, the raw `DeviceRequest` appears.
   Only there can `readerAuth` be signature-verified, because it is bound to the SessionTranscript.
   We already do this (`ProximityService.verifyReader`) — but today only to populate the transaction
   log, *after* the response is built. On iOS it should gate: throw before returning bytes.
3. `validateConsistency(request:rawRequest:)` is an **empty function** in the reference
   (`// proposed function in the wwdc video, to be implemented`). It is the check that what the OS
   showed the user matches what we are about to sign. We decode the `DeviceRequest` anyway, so
   comparing doctype / namespace / element sets against `context.request` is nearly free. Implement it.

Also worth knowing: neither the reference nor our `respondDcApiMdoc` supports per-claim consent — both
disclose `requested ∩ held`. If per-claim selection is a requirement, `respondDcApiMdoc` needs the
resolve/respond split the remote and proximity flows already have.

### P4 — API shape

`respondDcApiMdoc` living on `wallet.proximity` while `startDcApi` lives on `wallet.presentation` is
an artifact of where the CBOR lived, not a model the caller recognizes. A `wallet.dcApi` service with
a single protocol-tagged entry point would let one app codebase target both platforms and absorb a
future Apple `openid4vp` scene without touching call sites:

```swift
switch request {
case .openid4vp(let json, let origin):            // Android today, iOS if Apple ships it
case .isoMdoc(let deviceRequest, let encInfo, let origin):   // both platforms
}
```

Not urgent; do it when the iOS adapter lands, so both callers move at once.

## Verdict

Supporting both protocols *simultaneously* is already true of the SDK core and true on Android in
production. On iOS it is capped at `org-iso-mdoc` by Apple, and no amount of work on our side lifts
that cap. The tractable goal is **`org-iso-mdoc` parity on iOS**, gated on P0 (Apple SecureArea +
shared-keychain storage). The reference implementation is a usable blueprint for the extension
plumbing and a *non*-blueprint for its security checks.

Watch item: if Apple adds an OpenID4VP scene, `startDcApi` is already implemented, tested, and
verified against `verifier.eudiw.dev` on Android. The iOS adapter would grow one `case`.

## Sources

- [IdentityDocumentServices](https://developer.apple.com/documentation/identitydocumentservices) /
  [IdentityDocumentServicesUI](https://developer.apple.com/documentation/identitydocumentservicesui) — Apple
- [iOS/iPadOS platform notes](https://digitalcredentials.dev/docs/references/platforms/ios/) — digitalcredentials.dev
- [Online Identity Verification with the Digital Credentials API](https://webkit.org/blog/17431/online-identity-verification-with-the-digital-credentials-api/) — WebKit
- [Digital Credentials API: Secure and private identity on the web](https://developer.chrome.com/blog/digital-credentials-api-shipped) — Chrome
- [Digital Credentials API (2026): Chrome, Safari & Firefox](https://www.corbado.com/blog/digital-credentials-api) — Corbado
- `eu-digital-identity-wallet/av-lib-ios-w3c-dc-api` @ v0.20.1 — the reference `org-iso-mdoc` handler
