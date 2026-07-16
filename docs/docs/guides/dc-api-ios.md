---
title: Digital Credentials API (iOS)
---

# Digital Credentials API (iOS)

The [W3C Digital Credentials API](https://w3c-fedid.github.io/digital-credentials/) lets a website call
`navigator.credentials.get({ digital })` and have the OS mediate a wallet selector — no QR, no HTTP
round-trip. On iOS this runs through Apple's **[IdentityDocumentServices](https://developer.apple.com/documentation/identitydocumentservices)**
framework (iOS/iPadOS 26+): your wallet ships a **provider app extension** that the system wakes to answer
requests. The SDK does the credential logic; this guide wires it into iOS.

The `ios/` package ships this end to end in the **`AppleDcApi`** module, and `demo-ios/` (Axle Wallet)
assembles it. The code below shows what it does and how to adapt it.

## The platform ceiling — `org-iso-mdoc` only

Apple routes exactly **one** DC API protocol to third-party wallets: **`org-iso-mdoc`** (ISO/IEC TS
18013-7:2025 Annex C). OpenID4VP over the browser DC API is **not reachable on iOS** — and this is a
platform constraint, not an SDK limitation.

| Protocol | Android (Credential Manager) | iOS (IdentityDocumentServices) | SDK entry point |
| --- | --- | --- | --- |
| `openid4vp-v1-unsigned` / `-signed` | ✅ | ❌ platform | `wallet.presentation.startDcApi(json, origin)` |
| `org-iso-mdoc` | ✅ | ✅ | `wallet.proximity.respondDcApiMdoc(deviceRequest, encryptionInfo, origin)` |

The evidence is in the frameworks themselves: `IdentityDocumentServicesUI.IdentityDocumentRequestScene`
and `IdentityDocumentServices.IdentityDocumentWebPresentmentRequest` each have exactly **one** conforming
type — `ISO18013MobileDocumentRequestScene` / `ISO18013MobileDocumentRequest`. Every iOS browser is
WebKit, so no iOS browser routes `openid4vp` regardless of engine. The W3C community reference states it
for iOS: *"ISO 18013-7 Annex C for presentation. OpenID for Verifiable Presentations (Annex D) is not
supported."*

:::note OpenID4VP still works on iOS — just not over the browser DC API
`wallet.presentation.startDcApi` stays compiled and tested; it simply has no browser caller on iOS until
Apple ships a second scene type. Serve browser-mediated OpenID4VP requests through the same-device deep
link / cross-device `request_uri` flows instead (`wallet.presentation.start(requestUri)`), and verifier
front-ends should hide the OpenID4VP DC API option on Safari/iOS. Only the *browser-mediated DC API*
variant of OpenID4VP is unavailable.
:::

Both entry points are cross-platform (identical in Kotlin and Swift). Everything else on this page is iOS
provider plumbing.

## How iOS differs from Android

| | Android (Credential Manager) | iOS (IdentityDocumentServices) |
| --- | --- | --- |
| Registration | credential DB (CBOR) + protocol list | `MobileDocumentRegistration` per docType |
| Matcher | wallet ships a WASM matcher | **none** — the OS owns matching + the selector |
| Request handler | a translucent `Activity` (in-process) | a **separate provider app extension** (own process) |
| Request shape | one request object | **two**: a typed `context.request` (display) + the raw `DeviceRequest` (sign) |
| Presentable formats | mdoc + SD-JWT VC | **mdoc only** |

The two big consequences on iOS: (1) there is **no matcher** to write — this removes the whole Android
WASM-matcher problem; and (2) the request handler is a **separate process**, so it must share the app's
keys and stored credentials through App Group + Keychain sharing.

## Architecture: the app registers, the extension answers

```
   Axle Wallet app                          AxleWalletIDProvider (extension)
   ───────────────                          ───────────────────────────────
   • has the doctype entitlement            • IdentityDocumentProvider (@main)
   • DcApiRegistrar.sync(wallet)   ──┐       • ISO18013MobileDocumentRequestScene
     on every credential change      │        → your consent view
                                     │       • signs DeviceResponse, HPKE-seals it
        shared App Group  ◄──────────┴──────►  reads the SAME credentials + device keys
        shared Keychain group                  (separate process)
```

The browser wakes the **extension**, not the app. So the extension builds a `Wallet` from the *same*
adapters the app uses, pointed at the *same* shared group — it reads the credential the app issued and
signs the `DeviceResponse` with that credential's Secure Enclave device key.

## 1. Entitlements & capabilities

Three capabilities, split across the app and the extension:

| Capability | App | Extension |
| --- | --- | --- |
| `com.apple.developer.identity-document-services.document-provider.mobile-document-types` | ✅ (the doctypes you serve) | — |
| `com.apple.security.application-groups` (`group.…`) | ✅ | ✅ |
| Keychain Sharing (`$(AppIdentifierPrefix)…`) | ✅ | ✅ |

The doctype entitlement belongs on the **app**, because the app is what calls
`IdentityDocumentProviderRegistrationStore`. It is an **Apple-approved, managed** entitlement: every
servable doctype must be listed in the array, and a doctype absent from it cannot be registered or served.

```xml
<!-- AxleWallet.entitlements (app) -->
<key>com.apple.developer.identity-document-services.document-provider.mobile-document-types</key>
<array>
  <string>org.iso.18013.5.1.mDL</string>
  <string>eu.europa.ec.eudi.pid.1</string>
</array>
```

:::warning The entitlement is enforced at runtime
Without it, the extension installs but registration fails with `notAuthorized`, so Safari never offers
the wallet. Confirm it made it into the signed build:

```bash
codesign -d --entitlements :- "/path/to/Axle Wallet.app"
# expect the mobile-document-types key with a non-empty array
```
:::

## 2. Shared key custody (prerequisite)

`kSecAttrAccessGroup` is **fixed when a Secure Enclave key is created and cannot be changed afterwards**,
and SE private keys cannot be exported. So the app must create its keys under the **shared** keychain
access group from day one — otherwise no extension can ever sign with them, and the only remedy is
re-issuance. Build both the app's and the extension's `SecureArea` / `StorageDriver` with the shared group:

```swift
let group = "P3A48743C4.com.hopae.axle.wallet"   // $(AppIdentifierPrefix) + shared id
let secureArea = SecureEnclaveSecureArea(accessGroup: group)
let storage    = KeychainStorageDriver(accessGroup: group)
```

`AppleSharedGroups` in `AppleCore` centralizes the App Group + keychain group strings so the app and
extension can't drift.

## 3. Register documents

Registration is one call per stored mdoc credential — **no matcher, no database**. Run it on app start
and again whenever `wallet.credentials.changes()` emits (mirrors Android's re-register-on-change):

```swift
@available(iOS 26.0, *)
enum DcApiRegistrar {
  static func sync(wallet: Wallet) async {
    let store = IdentityDocumentProviderRegistrationStore()
    let wanted = try await wallet.credentials.list().reduce(into: [String: MobileDocumentRegistration]()) {
      guard case let .msoMdoc(docType) = $1.format,           // mdoc only — SD-JWT VC can't be served
            case let .issued(_, validity, _) = $1.lifecycle else { return }
      $0[$1.id.value] = MobileDocumentRegistration(
        mobileDocumentType: docType,
        supportedAuthorityKeyIdentifiers: [],                 // no issuer filtering — surface the reader instead
        documentIdentifier: $1.id.value,
        invalidationDate: validity?.validUntil)
    }
    for existing in (try? await store.registrations) ?? [] where wanted[existing.documentIdentifier] == nil {
      try? await store.removeRegistration(forDocumentIdentifier: existing.documentIdentifier)   // prune stale
    }
    for reg in wanted.values { try? await store.addRegistration(reg) }                          // upsert current
  }
}
```

:::note `notAuthorized` at registration
Almost always one of: the doctype isn't in the app's entitlement array; the managed capability isn't
approved for the App ID; or the **extension bundle failed to install** (see §4 — an invalid extension
makes the whole provider invalid, so `addRegistration` is refused). Register each document independently
and log the docType so you can tell which.
:::

## 4. The provider extension

The extension entry point is tiny — a scene that hands each request to your SwiftUI consent view:

```swift
import ExtensionKit
import IdentityDocumentServicesUI

@main
struct AxleDocumentProvider: IdentityDocumentProvider {
  var body: some IdentityDocumentRequestScene {
    ISO18013MobileDocumentRequestScene { context in
      DcApiConsentView(context: context)      // your consent UI — the OS hosts it
    }
  }
  func performRegistrationUpdates() async {}   // the app owns registration
}
```

### Xcode target setup

This is an **ExtensionKit** extension, not a legacy app extension — the difference is what makes it
installable:

| Setting | Value |
| --- | --- |
| Product type | `com.apple.product-type.extensionkit-extension` |
| Embed build phase | **Embed ExtensionKit Extensions** → `dstSubfolderSpec = 16`, `$(EXTENSIONS_FOLDER_PATH)` |
| Info.plist | `EXAppExtensionAttributes.EXExtensionPointIdentifier = com.apple.identity-document-services.document-provider-ui` |
| Entitlements | App Groups + Keychain sharing only |

:::warning The install gotcha
If you embed the `.appex` as a **legacy** app extension (into `PlugIns/`), `installd` treats it as a
PlugInKit bundle and rejects it: *"Appex bundle … does not define an NSExtension dictionary."* ExtensionKit
extensions ship in **`Contents/Extensions/`** (`$(EXTENSIONS_FOLDER_PATH)`) and declare
`EXAppExtensionAttributes`, not `NSExtension`. Verify: the built app has `AxleWallet.app/Extensions/…​.appex`.
:::

## 5. The two-phase request & building the response

Apple's flow is deliberately two-phase:

- **Pre-consent** you have the OS-parsed, typed `context.request` — the documents, namespaces, and
  elements to **display**, plus `context.requestingWebsiteOrigin` and the reader's certificate chain
  (`requestAuthentications`). Build your consent screen from this.
- **Post-consent**, inside `context.sendResponse { rawRequest in … }`, the **raw** request bytes arrive —
  `rawRequest.requestData` is the JSON `{ deviceRequest, encryptionInfo }` (both base64url CBOR). This is
  what you actually sign.

```swift
try await context.sendResponse { rawRequest in
  let data = try await DcApiResponder.responseData(
    rawRequestData: rawRequest.requestData,
    origin: context.requestingWebsiteOrigin,
    wallet: extensionWallet)
  return ISO18013MobileDocumentResponse(responseData: data)   // Apple wants raw Data
}
```

`DcApiResponder` extracts `{ deviceRequest, encryptionInfo }`, normalizes the origin (trim any trailing
`/` — it changes the SessionTranscript hash), and calls the SDK:

```swift
let base64url = try await wallet.proximity.respondDcApiMdoc(
  deviceRequestBase64: deviceRequest, encryptionInfoBase64: encryptionInfo, origin: origin)
let data = Data(base64urlDecoded: base64url)   // respondDcApiMdoc returns base64url; Apple's API takes Data
```

`respondDcApiMdoc` builds the mdoc `DeviceResponse` over the ISO 18013-7 **dcapi** SessionTranscript
`[null, null, ["dcapi", SHA-256(CBOR([encryptionInfoB64, origin]))]]`, **HPKE-seals** it (RFC 9180 base
mode, `DHKEM(P-256, HKDF-SHA256) / HKDF-SHA256 / AES-128-GCM`) to the verifier's `recipientPublicKey`, and
returns `base64url(CBOR(["dcapi", { enc, cipherText }]))`. This is byte-for-byte identical to the Android
path and to the EUDI reference — the HPKE + transcript live in the SDK (`Hpke.sealBaseP256`, `MDoc`
module), so no platform HPKE is needed. See the [Android DC API guide](./dc-api#4-org-iso-mdoc-and-hpke)
for the wire format.

## 6. Reader authentication — the verified badge

ISO 18013-5 §9.1.4 lets the verifier sign its request (`readerAuth`). Two independent things follow, and
iOS's two-phase API splits them across the timeline:

- **Identity trust (the badge)** — does the reader's certificate chain to a trusted reader anchor? This is
  checkable **pre-consent** from `context.request.requestAuthentications`, so the consent screen shows a
  *Verified* / *Unverified* pill. The extension is offline, so the app caches its resolved reader anchors
  into the shared App Group (`DcApiReaderTrust`) and the extension validates the chain against them with
  `SecTrust`.
- **Signature validity** — is the `readerAuth` COSE signature over the SessionTranscript valid? This needs
  the raw request, so it's only checkable **post-consent**.

Neither hard-blocks: an unverified or unknown reader simply presents as *Unverified* and sharing proceeds —
**matching Android**, which surfaces the reader but does not refuse. (A tampered request is already useless
to an attacker: the response is HPKE-bound to the origin + transcript the verifier expects.)

## 7. Consent consistency — an iOS-specific check

Because iOS hands you the request **twice** — once to display, once to sign — the two representations
could in principle diverge. Apple recommends confirming they match (their reference leaves it a stub);
the SDK adapter implements it. Before signing, decode the raw `DeviceRequest` and confirm it asks for
**nothing** the consent screen did not show; refuse otherwise:

```swift
for docRequest in deviceRequest.docRequests {
  guard let shownNamespaces = shown[docRequest.docType] else { throw .inconsistentRequest }
  for (namespace, elements) in docRequest.requested {
    for element in elements where !(shownNamespaces[namespace] ?? []).contains(element.identifier) {
      throw .inconsistentRequest   // never sign an attribute the user didn't see
    }
  }
}
```

Android has no equivalent because its DC API hands the app a **single** request object — there is nothing
to cross-check. In normal operation this check never fires (the OS parses `context.request` from the same
bytes); it exists to defend the display-vs-sign boundary the platform introduces.

## 8. Biometric confirmation

Gate `Share` on Face ID / Touch ID exactly like the in-app present flows. The extension is a separate
process, so read the biometric preference from the shared App Group (the app mirrors it there) and prompt
with `LocalAuthentication` (the extension's `Info.plist` needs `NSFaceIDUsageDescription`):

```swift
if biometricEnabled, await !LAContext().authenticate(reason: "Confirm to share your ID") {
  return   // cancelled — do not send a response
}
```

Honour the user's setting: no prompt when biometric is off, exactly like the remote / proximity flows.

## 9. Build & test

1. Install the signed build on an **iOS 26** device (the Secure Enclave + entitlements need real hardware).
2. Confirm registration: on app start / credential change you should see `registered N mdoc document(s)`.
3. Open an `org-iso-mdoc` DC API verifier in Safari (e.g. `verifier.eudiw.dev`), request an mDL or PID.
4. `navigator.credentials.get({ digital })` → the OS selector offers **Axle Wallet** → pick it → your
   consent view shows the reader, the attributes, and the *Verified* badge → Face ID → the signed,
   HPKE-encrypted `DeviceResponse` goes back to the verifier.

:::note
A response can still be rejected by the verifier's own issuer-trust policy — that's verifier-side, not the
wallet. For the reference iOS adapters (`AppleDcApi`) and demo (Axle Wallet), see the
[iOS adapter modules](./ios-adapters) and [iOS demo](../ios-demo) pages.
:::
