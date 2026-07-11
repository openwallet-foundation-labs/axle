# Play Integrity — setup & verification

Play Integrity attests that a request comes from a **genuine app on a genuine Android device**. The wallet
requests a token from Google, sends it to the Wallet Provider, and the backend has Google **decode** it into a
verdict. Two signals matter:

- **`deviceIntegrity`** — is the device a genuine, uncompromised Android device? Works regardless of how the
  app is distributed.
- **`appIntegrity`** — is this the app Google Play distributed? Only `PLAY_RECOGNIZED` for a build that came
  through a Play track (see §7); a side-loaded build is `UNRECOGNIZED_VERSION`.

The token is an **encrypted JWE** (`A256KW`/`A256GCM`) — the wallet only relays it; the verdict is readable
only after Google decodes it, which needs a service account.

---

## 1. Google Cloud project

1. Open the [Google Cloud console](https://console.cloud.google.com) and **create or select a project**.
   (An existing/shared company project is fine — Play Integrity via `setCloudProjectNumber` works even for
   apps not distributed on Play.)
2. Copy the **project _number_** (a long integer, not the project _id_) — *Project info* card or
   ⚙️ *Settings*. This is what the client passes as `cloudProjectNumber`.
3. **APIs & Services → Library → “Play Integrity API” → Enable.** (If you lack permission, an admin enables
   this one API — it's harmless.)

## 2. Service account (backend decode)

The backend authenticates the `decodeIntegrityToken` call with a service account in the same project.

1. **IAM & Admin → Service Accounts → Create service account.**
2. Create a **JSON key** for it and download it. **This is a credential — never commit it.** Point the
   backend at it with `GOOGLE_APPLICATION_CREDENTIALS=/path/to/key.json`.

> The **project number is not secret** (it ships inside every APK). The **service-account JSON is** — keep it
> out of the repo and out of logs.

## 3. Client (the wallet)

`android/attestation`'s `PlayIntegrityTokenProvider` requests the token:

```kotlin
val integrity = PlayIntegrityTokenProvider(
    context,
    cloudProjectNumber = 1048824403731L,        // the project number from §1
    fallback = DevIntegrityTokenProvider(),      // demo: attempt real → log → dev fallback; production: null
    logger = logger,
)
```

Pass `fallback = null` in production so a failed integrity check surfaces instead of silently degrading to the
`dev-integrity:<nonce>` token. The token is bound to the Wallet Provider's challenge nonce.

## 4. Backend (the Wallet Provider)

`IntegrityService.verifyPlayIntegrity` turns on when configured:

```sh
cd wallet-provider
PLAY_INTEGRITY_PACKAGE_NAME=com.hopae.axle.wallet \
GOOGLE_APPLICATION_CREDENTIALS=/path/to/service-account.json \
npm run start
```

It calls Google `decodeIntegrityToken`, checks the nonce (anti-replay) and the app/device verdicts. Without
these env vars it falls back to the DEV stub that only accepts `dev-integrity:<nonce>`.

## 5. Decode a token by hand

`tools/decode-integrity.mjs` prints the raw verdict — handy while wiring things up:

```sh
cd wallet-provider
GOOGLE_APPLICATION_CREDENTIALS=/path/to/service-account.json \
PLAY_INTEGRITY_PACKAGE_NAME=com.hopae.axle.wallet \
node tools/decode-integrity.mjs "<integrity-token>"
```

Grab a token from the device with `adb logcat` (the demo can log one during development); Play Integrity
tokens are short-lived, so decode promptly.

## 6. Reading the verdict

```json
{ "tokenPayloadExternal": {
  "requestDetails":  { "requestPackageName": "…", "nonce": "…" },
  "appIntegrity":    { "appRecognitionVerdict": "PLAY_RECOGNIZED | UNRECOGNIZED_VERSION | UNEVALUATED", … },
  "deviceIntegrity": { "deviceRecognitionVerdict": ["MEETS_DEVICE_INTEGRITY", …] },
  "accountDetails":  { "appLicensingVerdict": "LICENSED | UNLICENSED | UNEVALUATED" }
}}
```

**Verified example** (this repo, a side-loaded debug build of `com.hopae.axle.wallet` on a Samsung SM-F731N):
`deviceIntegrity: MEETS_DEVICE_INTEGRITY` (genuine device) + `appIntegrity: UNRECOGNIZED_VERSION` (not from
Play — the `certificateSha256Digest` is the debug signing key) + `appLicensingVerdict: UNEVALUATED`.

## 7. Getting `PLAY_RECOGNIZED` (Play Console internal testing)

`appIntegrity` is `UNRECOGNIZED_VERSION` for a side-loaded build. To get `PLAY_RECOGNIZED` **without a public
release or review**, use the **Internal testing** track:

1. Build a **signed release AAB** (the debug APK won't do — Play recognises the Play-distributed, Play-signed
   build, not a locally debug-signed one).
2. [Play Console](https://play.google.com/console) → **Create app** (or pick an existing one) → **Test and
   release → App integrity → Play Integrity API → link the Cloud project** from §1.
3. **Test and release → Testing → Internal testing → Create release → upload the AAB.** Add yourself as an
   internal tester.
4. Install the app **via the internal-testing opt-in link** (so Play distributes it, signed with the Play app
   signing key).
5. Re-run the check — `appIntegrity` is now `PLAY_RECOGNIZED`.

Internal testing is available almost immediately (no public review); you only fill in a few Play Console
declarations (content rating, data safety, target audience) to activate the track.
