---
title: Digital Credentials API (Android)
---

# Digital Credentials API (Android)

The [W3C Digital Credentials API](https://w3c-fedid.github.io/digital-credentials/) lets a website
call `navigator.credentials.get({ digital })` and have the OS mediate a wallet selector — no QR, no
HTTP round-trip. The SDK does the credential logic; this guide wires it into the **Android Credential
Manager** so a browser can invoke your wallet.

The wallet answers three DC API protocols, all verified on-device against `verifier.eudiw.dev` and
`digital-credentials.dev`:

| Protocol | What it is | SDK entry point |
| --- | --- | --- |
| `openid4vp-v1-unsigned` | OpenID4VP 1.0 request object (plain JSON) | `wallet.presentation.startDcApi(json, origin)` |
| `openid4vp-v1-signed` | OpenID4VP 1.0 JAR — `{"request":"<JWS>"}` | `wallet.presentation.startDcApi(json, origin)` |
| `org-iso-mdoc` | ISO 18013-7 Annex C raw mdoc, HPKE-encrypted | `wallet.proximity.respondDcApiMdoc(deviceRequest, encryptionInfo, origin)` |

Both entry points are cross-platform (identical in Kotlin and Swift). Everything else on this page is
Android provider plumbing.

:::tip This plumbing is packaged
The `android/dcapi` adapter module ships this end to end — `DcApiRegistrar` (Credential Manager
registration + matcher), `DcApiRequest` / `DcApiResult` (envelope parsing + marshalling), and
`DcApiBranding` (OS-selector logo). Depend on it and the walkthrough below is done for you; the code here
shows what it does under the hood, and how to adapt it. See [Android adapters & demo](../android-demo).
:::

:::note Why a custom matcher
The Credential Manager runs a **matcher** — a small WASM program — to filter your credentials against
an incoming request before showing the selector. The androidx `OpenId4VpRegistry` bundles a matcher
that (as of `registry:1.0.0-alpha04`) does **not** recognize the `openid4vp-v1-*` protocol IDs current
EUDI verifiers send, and never the raw `org-iso-mdoc` protocol. So we ship a matcher WASM ourselves and
register it through the lower-level Google Play Services **IdentityCredentials** API. DC API therefore
needs a GMS device; every other capability (issuance, remote/proximity presentation) is unaffected
without it.
:::

## 1. Dependencies

```kotlin
implementation("androidx.credentials:credentials:1.6.0-rc01")
implementation("com.google.android.gms:play-services-identity-credentials:16.0.0-alpha08")
```

Plus two bundled assets:

- `assets/identitycredentialmatcher.wasm` — the matcher program (e.g. the one from
  [Multipaz](https://github.com/openwallet-foundation-labs/identity-credential)).
- `assets/privileged_allowlist.json` — Google's privileged-browser list, from
  `https://www.gstatic.com/gpm-passkeys-privileged-apps/apps.json` (used to resolve web origins).

## 2. Register credentials

Registration hands the Credential Manager two things: the **matcher** and a **credential database** it
can read. Build the database as CBOR in the matcher's schema, declare the protocols you support, and
register it under both credential types. Re-register whenever credentials change (issue / delete).

```kotlin
object DcApiRegistrar {
    private val PROTOCOLS = listOf(
        "openid4vp-v1-signed", "openid4vp-v1-unsigned", "openid4vp-v1-multisigned", "org-iso-mdoc", "openid4vp",
    )

    suspend fun register(context: Context, wallet: Wallet) {
        val creds = wallet.credentials.list()
        val db = buildDatabase(creds)                                  // CBOR: { protocols, credentials }
        val matcher = context.assets.open("identitycredentialmatcher.wasm").use { it.readBytes() }
        val client = IdentityCredentialManager.getClient(context)
        // Register under the androidx digital-credential type AND the legacy Credman type.
        listOf("androidx.credentials.TYPE_DIGITAL_CREDENTIAL", "com.credman.IdentityCredential").forEach { type ->
            client.registerCredentials(
                RegistrationRequest(credentials = db, matcher = matcher, type = type, requestType = "", protocolTypes = emptyList()),
            )
        }
    }
}
```

The credential database is a CBOR map `{ "protocols": [...], "credentials": [...] }`. Each credential
entry carries display fields plus a format-specific block the matcher searches:

```kotlin
// mSO mdoc entry — the matcher matches its docType + namespaced elements against the DeviceRequest.
map(common + ("mdoc" to map(listOf(
    "documentId" to txt(c.id.value),
    "docType"    to txt(f.docType),
    "namespaces" to map(namespaces),   // ns -> { element -> [displayName, value, rawMatchString] }
))))

// SD-JWT VC entry — matched by vct + claim names.
map(common + ("sdjwt" to map(listOf(
    "documentId" to txt(c.id.value),
    "vct"        to txt(f.vct),
    "claims"     to map(claims),
))))
```

Run `register` on app start and again whenever `wallet.credentials.changes` emits.

## 3. Provider activity

Declare one activity for the `GET_CREDENTIAL` intent — no UI (the OS selector is the consent). It needs
**both** the androidx and the identity-credentials actions:

```xml
<activity
    android:name=".GetCredentialActivity"
    android:exported="true"
    android:theme="@android:style/Theme.Translucent.NoTitleBar">
    <intent-filter>
        <action android:name="androidx.credentials.registry.provider.action.GET_CREDENTIAL" />
        <action android:name="androidx.identitycredentials.action.GET_CREDENTIALS" />
        <category android:name="android.intent.category.DEFAULT" />
    </intent-filter>
</activity>
```

Pull the request envelope, then route on protocol. The DC API request is
`{"requests":[{"protocol":"…","data":{…}}]}` — dispatch `org-iso-mdoc` to the mdoc path and everything
else to the OpenID4VP path:

```kotlin
@OptIn(androidx.credentials.ExperimentalDigitalCredentialApi::class)
override fun onCreate(savedInstanceState: Bundle?) {
    val request = PendingIntentHandler.retrieveProviderGetCredentialRequest(intent) ?: return finishNoResult()
    val option = request.credentialOptions.filterIsInstance<GetDigitalCredentialOption>().firstOrNull() ?: return finishNoResult()
    val origin = request.callingAppInfo.getOrigin(privilegedAllowlistJson) ?: appOrigin(request)

    // org-iso-mdoc (ISO 18013-7): raw mdoc DeviceRequest -> HPKE-encrypted DeviceResponse.
    val mdoc = matchProtocol(option.requestJson, listOf("org-iso-mdoc", "org.iso.mdoc"))
    if (mdoc != null) {
        val (proto, data) = mdoc
        lifecycleScope.launch {
            val response = wallet.proximity.respondDcApiMdoc(
                data.getString("deviceRequest"), data.getString("encryptionInfo"), origin,
            )
            val content = JSONObject().put("protocol", proto)
                .put("data", JSONObject().put("response", response))
            respond(DigitalCredential(content.toString())); finish()
        }
        return
    }

    // openid4vp-v1-unsigned / -signed / -multisigned. Capture the matched protocol — the response envelope must echo it.
    val vp = matchProtocol(option.requestJson,
        listOf("openid4vp-v1-unsigned", "openid4vp-v1-signed", "openid4vp-v1-multisigned")) ?: return failAndFinish("no openid4vp request")
    val (vpProtocol, vpData) = vp
    lifecycleScope.launch {
        val session = wallet.presentation.startDcApi(vpData.toString(), origin)
        val resolved = session.state.first { it is RequestResolved || it is Failed } as RequestResolved
        session.respond(PresentationSelection.auto(resolved.request))
        val done = session.state.first { it.isTerminal } as PresentationState.Completed
        // Wrap the SDK's inner response ({vp_token} | {response:<JWE>}) in the platform's {protocol, data}
        // envelope, echoing the request protocol — recent Chrome rejects a response with no top-level `protocol`.
        val content = JSONObject().put("protocol", vpProtocol).put("data", JSONObject(done.dcApiResponse!!))
        respond(DigitalCredential(content.toString())); finish()
    }
}
```

Both paths return the same `{"protocol", "data"}` envelope; the `DcApiResult.openId4VpResponseJson(protocol, response)` /
`mdocResponseJson(protocol, response)` helpers in `android/dcapi` build it for you (echoing the matched request protocol).

## 4. org-iso-mdoc and HPKE

The `org-iso-mdoc` request `data` is `{ "deviceRequest": base64url(CBOR), "encryptionInfo": base64url(CBOR) }`
— a bare ISO 18013-5 `DeviceRequest` plus the verifier's ephemeral encryption key. `respondDcApiMdoc`:

1. builds the `DeviceResponse` for the requested docType, signed over the ISO 18013-7 **dcapi**
   `SessionTranscript` `[null, null, ["dcapi", SHA-256(CBOR([encryptionInfoB64, origin]))]]`;
2. **HPKE-seals** it (RFC 9180 base mode, `DHKEM(P-256, HKDF-SHA256) / HKDF-SHA256 / AES-128-GCM`) to the
   verifier's `recipientPublicKey`, with `info = CBOR(SessionTranscript)` and empty `aad`;
3. returns `base64url(CBOR(["dcapi", { "enc": …, "cipherText": … }]))`.

HPKE lives in the SDK (`Hpke.sealBaseP256`, Kotlin `mdoc` module / Swift `MDoc`), verified against the
RFC 9180 Appendix A.3 test vector — so the crypto is portable and needs no platform HPKE. The demo just
wraps the returned string in `{"protocol","data":{"response":…}}`.

## 5. Verifier origin

`callingAppInfo.getOrigin(allowlistJson)` returns the **web origin** (e.g. `https://verifier.example`)
when the caller is a privileged browser in your allowlist. For a **native app** verifier the origin is
empty — derive it from the caller's signing certificate:

```
android:apk-key-hash:<base64url SHA-256 of signingCertificateHistory[0]>
```

The SDK binds this origin into the mdoc `SessionTranscript` (ISO 18013-7 Annex C) / SD-JWT KB-JWT, so the
response is cryptographically bound to the caller that requested it.

### `expected_origins` — request replay protection

Binding the *response* to the origin does not stop the *request* from being replayed. A signed request
object is a bearer artifact: a malicious site can present one captured from a legitimate verifier, and
its signature still verifies — so the wallet would show that verifier's trusted identity for a request
the attacker initiated.

OpenID4VP Appendix A.2 closes this with `expected_origins`, and the SDK enforces it:

| Request | Rule |
| --- | --- |
| **signed** (`{"request":"<JWS>"}` or a bare JWS) | `expected_origins` is **REQUIRED**. The SDK rejects the request unless it is a non-empty array containing the platform-supplied origin. `client_id` is also required. |
| **unsigned** (plain JSON) | The origin *is* the verifier's identity. The SDK **ignores** both `expected_origins` and any `client_id` present. |

Both inputs come from channels the calling page cannot control: the origin is supplied by the platform,
and `expected_origins` sits inside the signature-protected payload. A mismatch raises
`VpException.InvalidRequest` / `VpError.invalidRequest` (OpenID4VP's `invalid_request`).

:::note Self-asserted, not proof of ownership
`expected_origins` prevents replay of *someone else's* signed request. It does not prove the verifier
owns those origins — an attacker with a valid certificate can sign their own request listing their own
origin. Whether to trust that `client_id` is the trust framework's job (`readerAnchorsDer`).
:::

## 6. Test

1. Registration runs on app start (log `registered N credential(s)`), so the wallet is now a provider.
2. Open a DC-API verifier in Chrome (`verifier.eudiw.dev` or `digital-credentials.dev`) and pick a
   protocol — try **openid4vp** (unsigned and signed) and **org-iso-mdoc** (mDL).
3. `navigator.credentials.get({ digital })` → the OS shows a selector including your wallet → pick it →
   `GetCredentialActivity` routes to the right SDK path and returns the response.

:::note
Some Chrome builds gate this behind `chrome://flags` → "Digital Credentials API". A response can still be
rejected by the verifier's own issuer-trust policy — that's verifier-side, not the wallet.
:::
