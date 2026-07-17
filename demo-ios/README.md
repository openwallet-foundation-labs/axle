# EUDI Wallet SDK — iOS Demo (Axle Wallet)

A SwiftUI **debug wallet** driving the Swift SDK with the real Apple adapters (`../ios`): Secure
Enclave keys, keychain storage, OpenID4VCI/VP, DC API provider extension, ISO 18013-5 proximity
(holder + reader). The UI is a 1:1 port of the Android demo (`../demo`) — keep them in sync
(`CredentialVisuals`, `CredentialContent`, screen structure).

## Development notes

### Build

- **Xcode only** — neither this app nor `../ios` builds on Linux; SourceKit "No such module"
  diagnostics on non-Mac checkouts are noise. Changes authored off-Mac are unverified until Xcode
  builds them.
- Uses the shared keychain access group + App Group so the `AxleWalletIDProvider` extension (DC API)
  can read credentials and sign with their keys.

### Gotchas

- **New mdoc doctype? Touch the entitlements.** DC API requests only reach the wallet for doctypes
  listed in `AxleWallet/AxleWallet.entitlements` (see `../ios/README.md`). The provisioning profile
  must carry the entitlement too.
- **Trust verdicts are stamped at issuance.** The "Credential signature" / "Issuer registration" rows
  show the verdict computed when the credential was issued. After fixing anything in the SDK's trust
  stack, **delete and re-issue** stored credentials — they will not re-verify themselves.
- **Presenting is request-driven by design.** The document detail page deliberately has no
  proximity/present button; holder sharing starts from Home (Proximity quick action), and the holder
  answers whatever doctype the reader requests from the whole store.
- **Image claims render by element name.** The SDK exposes mdoc bstr values as base64url text; the
  demo detects `portrait`/`enrolment_portrait_image`/`signature_usual_mark` by name and renders
  thumbnails (`CredentialContent.swift` helpers, mirrored from android `ui/ClaimImage.kt`). New
  image-bearing elements must be added to both platforms' lists.
