# Spec Version Matrix

Specification versions this SDK implements and tracks. Unless a row says otherwise, every item is
implemented in both the Kotlin and Swift trees (line-for-line ports) and verified against shared golden
vectors (`vectors/`) and live interop where available.

Last clause-by-clause audit: **2026-07-09** (six anchor specs, both trees; see
[Detailed coverage & known gaps](#detailed-coverage--known-gaps)). Last change: **2026-07-15** — added the
trust / registration / attestation layer (ETSI TS 119 475 WRPRC incl. the intermediated flow, ETSI
TS 119 602 Trusted Lists), closed the Wallet Provider WUA + key-attestation loop (Play Integrity
`PLAY_RECOGNIZED`), and added ISO 18013-5 reader-side request signing.

Legend: ✅ implemented · 🟡 partial · ⬜ not yet.

## At a glance

| Area | Standard(s) | Status | Notes |
|---|---|---|---|
| Formats & crypto | CBOR (RFC 8949), COSE, JOSE/JWS, JWE, HPKE, X.509 PKIX | ✅ | in-house; verified against RFC vectors; JCA / swift-crypto only |
| Credential formats | SD-JWT VC · ISO/IEC 18013-5 mdoc | 🟡 · ✅ | mdoc implemented; SD-JWT VC verifier implemented, Type Metadata (§4) absent |
| Issuance | OpenID4VCI 1.0 + HAIP | ✅ | pre-auth & auth-code (PAR/PKCE/DPoP), key attestation, batch/deferred/notification/refresh, signed metadata, encrypted request+response; verified against the EUDI reference issuer |
| Presentation — remote | OpenID4VP 1.0 + HAIP | ✅ | DCQL, `direct_post(.jwt)`, signed requests + reader trust, `transaction_data`; verified against the EUDI reference verifier |
| Presentation — proximity | ISO/IEC 18013-5 | 🟡 | data model + session crypto + `deviceSignature`/`deviceMac` + reader auth complete (holder & reader); **BLE transport on both Android and iOS** (both modes, holder & reader); **NFC transport Android-only**. Device-to-device verified with Multipaz |
| Presentation — DC API | ISO/IEC 18013-7 · W3C Digital Credentials API | ✅ | origin-bound handover + HPKE-sealed mdoc response; OpenID4VP over the browser DC API |
| Trust & registration | ETSI TS 119 475 (WRPRC) · TS 119 602 (Trusted Lists) | ✅ | registrar-issued RP registration incl. the **intermediated** flow; JAdES trusted-list CA anchors |
| Attestation | WUA (attestation client auth) · key attestation | ✅ | Wallet Provider loop closed (Play Integrity `PLAY_RECOGNIZED`) |
| Revocation | IETF Token Status List | ✅ | fetch + verify + index lookup |
| Audit | ARF / GDPR transaction log | ✅ | presentations + issuances, queryable by type / party / time |

Open items (both language trees):

- **SD-JWT VC Type Metadata (§4)** — `vct` resolution / `extends` / display / JSON-schema, plus `vct#integrity`.
- **Trust cluster** — DCQL `trusted_authorities`; the `verifier_attestation` / `decentralized_identifier` / `openid_federation` client-ID prefixes; real-time revocation (CRL / OCSP / LOTL-2). Not a security boundary (the verifier re-validates issuer trust per OpenID4VP §6.1, DCQL matching is `SHOULD`).
- **iOS NFC proximity transport** — iOS ships the BLE transport (both modes, holder & reader); NFC engagement stays Android-only (iOS HCE is region-restricted).

Items marked a [deliberate non-goal](#deliberate-non-goals) (the legacy `vc+sd-jwt` typ, the TS-literal `OID4VPHandover`, 18013-7 Annex A website retrieval, …) are decisions, not to-dos.

## Formats & crypto

| Spec | Anchor version | Status |
|---|---|---|
| CBOR | RFC 8949 (deterministic encoding §4.2.1) | ✅ `cbor` / `CborCose` — RFC 8949 Appendix A vectors pass both languages; bytewise + length-first key ordering profiles |
| COSE | RFC 9052 §4.2 `COSE_Sign1` · RFC 9053 ES256/384/512 · RFC 9360 x5chain | ✅ verify (JCA / swift-crypto) + sign (`CoseSigner` → `SecureArea` port); COSE-WG Sign1 vectors pass. `COSE_Mac0` sign + verify (HMAC 256/256) |
| JOSE / JWS | RFC 7515 / 7518 subset (compact, ES256/384/512) | ✅ `sdjwt` / `SdJwt` — in-house, fixed-`alg` verification (no negotiation) |
| JWE | RFC 7518 ECDH-ES direct + A128/192/256GCM | ✅ Concat KDF (RFC 7518 Appendix C vectors) — encrypts `direct_post.jwt` / `dc_api.jwt` responses and OpenID4VCI Credential Requests; decrypts Credential Responses (`JweRecipientKey`). `kid` header per OpenID4VCI §10 |
| HPKE | RFC 9180 base mode — DHKEM(P-256, HKDF-SHA256) / HKDF-SHA256 / AES-128-GCM | ✅ `mdoc` `Hpke` / `MDoc` — **seal** (wallet) and **open** (verifier/reader) of the `org-iso-mdoc` DC API response (ISO 18013-7 Annex C). RFC 9180 A.3 vector pins `seal` both languages; `open` (KEM decap + AEAD open via `RecipientKey`) round-trips it and rejects tampered ciphertext / wrong `info` / wrong recipient |
| SD-JWT | RFC 9901 | ✅ issue / present / verify, KB-JWT, recursive & array disclosures, decoys; RFC disclosure vectors (83 entries) pass both languages. `alg=none` explicitly rejected on the issuer JWT and KB-JWT (§7.1(2.a)/§7.3(5.b)); KB-JWT `iat` validated against a configurable acceptable window (§7.3(5.e), `KbRequirement.maxAgeSeconds`/`skewSeconds`). Gaps: §7.1(6) `exp`/`nbf` enforced only in the VC layer, §8 JWS JSON serialization absent (optional) |
| SD-JWT VC | draft-ietf-oauth-sd-jwt-vc-17 (2026-07-06) | 🟡 `SdJwtVcVerifier` — typ/iss/vct enforcement, time validation, issuer-key resolution (`.well-known/jwt-vc-issuer` + x5c), holder binding, status extraction. **Type Metadata (§4) and `vct#integrity` entirely unimplemented**; the legacy `vc+sd-jwt` typ is rejected — a [deliberate non-goal](#deliberate-non-goals) |
| ISO/IEC 18013-5 mdoc | :2021 | ✅ `mdoc` / `MDoc` — `IssuerSigned`/MSO, `DeviceResponse`, selective disclosure, device signature **and `deviceMac`** (holder + reader), reader auth (§9.1.4). MSO digest SHA-256/384/512; a non-zero `DeviceResponse` status is surfaced on the reader (§8.3.2.1.2.3), `documentErrors`/per-document `errors` maps intentionally not modeled |
| X.509 PKIX | RFC 5280 | ✅ `trust` / `Trust` — chain validation (path build, validity, basic constraints), SAN, x509_san_dns / x509_hash; x5c adapters for SD-JWT VC issuers, mdoc issuer/reader, and signed issuer metadata |

## Issuance (OpenID4VCI)

| Spec | Anchor version | Status |
|---|---|---|
| OpenID4VCI | 1.0 Final (2025-09-16) | ✅ `openid4vci` — pre-authorized & authorization-code (+PAR), offer resolution, scope-preferred; **signed metadata** (§12.2.2 `Accept` negotiation + §12.2.3 `application/jwt` with `typ`/`alg`/`sub`/`iat`/`exp` rules); **live-issued a PID from the EUDI reference issuer (`issuer.eudiw.dev`, the EU reference implementation — not a production issuer)** and **live-verified signed metadata from `dev.issuer-backend.eudiw.dev`** (see `INTEROP.md`). **encrypted Credential Requests/Responses** (§8.2/§10, ECDH-ES + A*GCM, live-verified against `issuer.eudiw.dev`) — same on the **deferred endpoint** (§9.1); deferred issuance surfaces the §8.3 `interval` (`IssuanceState.Deferred(retryAfter)`) and handles §9.2 202 re-deferrals; **`credential_identifiers`** (§8.2 — request by `credential_identifier` when the token binds them); both key-proof mechanisms — `jwt` proofs with the `key_attestation` header, and the **`attestation` proof type** (Appendix F.3, `preferAttestationProof`) |
| PKCE | RFC 7636 (S256) | ✅ |
| DPoP | RFC 9449 | ✅ jti/htm/htu/ath + DPoP-Nonce retry |
| OAuth Attestation-Based Client Auth | draft (wallet attestation + PoP) | ✅ WUA client authentication during issuance |
| HAIP | 1.0 Final | ✅ issuance profile implemented (both languages) — PAR/DPoP/PKCE required, wallet attestation, key attestation, batch, deferred, notification, refresh-token reissuance, signed metadata policy (OpenID4VCI §12.2.2/§12.2.3) |

## Presentation (OpenID4VP & proximity)

| Spec | Anchor version | Status |
|---|---|---|
| OpenID4VP | 1.0 Final (2025-07-09), DCQL | ✅ `openid4vp` — DCQL engine (null wildcard, values, claim_sets, credential_sets), JAR request resolution, `vp_token` (SD-JWT+KB-JWT and mdoc `DeviceResponse` — `deviceSignature` or, when the verifier's `deviceauth_alg_values` requests it, `deviceMac` per ISO 18013-7 B.4.5), `direct_post` + `direct_post.jwt` (JWE — §8.3 `alg`-matched key selection, `kid` echo, `apv`-bound nonce), reader trust for signed requests, DC API `expected_origins` replay check (Appendix A.2), JAR hardening (`typ`, request-object `client_id` equality, `wallet_nonce`, case-sensitive `request_uri_method`), §8.5 Authorization Error Responses (`VpErrorCode` taxonomy + `reportError`; decline reports `access_denied` and follows the verifier's `redirect_uri`), DCQL `multiple` (per-query multi-credential vp_token), `require_cryptographic_holder_binding` (unbound SD-JWT VC presentation when the verifier allows), and `transaction_data` (§8.4 — per-credential binding + `invalid_transaction_data` validation; SD-JWT VC KB-JWT hash and mdoc B.2.1 device-signed element via a host binder). Gaps: DCQL `trusted_authorities` — see audit below |
| ISO/IEC 18013-5 device retrieval | :2021 §9 | 🟡 `proximity` / `Proximity` — QR **and NFC static + negotiated handover** engagement (negotiated: `MdocNfcEngagement` Handover Request / ReaderEngagement + `[Hs, Hr]` transcript, wired through `present`/`read` via `handoverRequestNdef`; static is the default), ECDH session keys (HKDF, salt = SHA-256 of the tag-24 SessionTranscript), `SessionEstablishment`/`SessionData` framing, encrypted exchange, reader authentication; **holder and reader** sides (`wallet.reader`). Device auth: `deviceSignature` **and `deviceMac`** end-to-end (holder derives the EMacKey via the `SecureArea` key-agreement port; `PresentationConfig.mdocDeviceAuth` — one knob shared with the OpenID4VP mdoc path). BLE (both modes, incl. the §8.3.3.1.1.4 **Ident** characteristic) transports ship for **both Android (demo host adapter) and iOS (`AppleProximity`, CoreBluetooth — both modes, holder & reader)**; the NFC APDU transport is **Android-only**. **Live device-to-device interop with Multipaz** (BLE both modes + NFC, see `INTEROP.md`) |
| ISO/IEC 18013-7 / DC API handover | :2025 Annex C | ✅ origin-bound mdoc `SessionTranscript` + **HPKE-sealed `org-iso-mdoc` response** for the Digital Credentials API. Annex B follows OpenID4VP 1.0 Final's handover, which superseded the TS-literal `OID4VPHandover`; Annex A (website REST retrieval) is a [deliberate non-goal](#deliberate-non-goals) |
| W3C Digital Credentials API | browser-mediated (dc_api / dc_api.jwt) | ✅ `wallet.presentation.startDcApi` — no HTTP, response object returned to the platform. The SD-JWT VC KB-JWT `aud` is `origin:<origin>` over the DC API (Appendix A.2), the verifier `client_id` for URL/QR |

## Status & audit

| Spec | Anchor version | Status |
|---|---|---|
| IETF Token Status List | draft-ietf-oauth-status-list | ✅ `statuslist` / `StatusList` — fetch + verify status token (signature + issuer chain), cached, index lookup |
| Transaction log (ARF / GDPR) | ARF transaction logging | ✅ `txlog` / `TransactionLog` — **presentations** (relying party id/name/trusted/chain, per-document disclosed claims) **and issuances** (issuer + credential type on success; **ERROR + message on a failed attempt** — start / deferred-complete / reissue); history/query by type/party/time |
| Real-time revocation (CRL / OCSP / LOTL Level 2) | RFC 5280 / RFC 6960 | ⬜ not implemented — revocation via the IETF Token Status List only |

## Trust, registration & attestation

| Spec | Anchor version | Status |
|---|---|---|
| ETSI TS 119 475 (RP registration / WRPRC) | v1.2.1 | ✅ `trust` `WRPRCVerifier` — validates the JAdES `rc-wrp+jwt` WRPRC against the registrar CA and binds it to the request-signing WRPAC (`organizationIdentifier`): a **direct** request binds to `sub`, an **intermediated** request (§5.1) to `intermediary.sub`/`act.sub` while `sub` stays the final RP. Surfaces entitlements, purpose, the intermediary, the **final-RP display name**, the attribute-scope check (**RPRC_21** — requested claims outside the registration), and the Token Status List result; also the self-declared `registrar_dataset` path with optional online confirmation via the registrar TS5 API (RPRC_16/18). Trust is **informational, not a gate** (ARF informed consent). Both languages |
| WRPRC / dataset transport | ETSI TS 119 472-2 §6.3 | ✅ read from the OpenID4VP request's `verifier_info` (`registration_cert` by value + `registrar_dataset`); surfaced on `VerifierInfo.registration` for the consent screen and the audit log |
| ETSI TS 119 602 (Trusted Lists) | v1.1.1 | ✅ `trustlist` `TrustedListClient` — fetches issuer / reader / registrar CA anchors from JAdES-signed Trusted Lists (verified to a pinned Scheme Operator), feeding `TrustConfig`; the sandbox Scheme Operator publishes them (`ecosystem/trusted-list`) |
| ISO 18013-5 reader authentication (signing) | §9.1.4 | ✅ the wallet's reader role signs its device requests with a `ReaderAuthSigner` (`WalletConfig.readerAuth`) so the holder can authenticate *who is asking*; the holder side already verified reader auth |
| Wallet Unit Attestation (WUA) | OAuth Attestation-Based Client Auth (draft) | ✅ `WalletAttestationProvider` port + `AttestationClientAuth` — instance registration → WUA client-auth JWT (`cnf.jwk` PoP) used at the Issuer; **e2e closed** against the `wallet-provider` backend (Play Integrity `PLAY_RECOGNIZED`, see `demo/RELEASE.md`) |
| Key attestation | OpenID4VCI §8.2.1.1 (`keyattestation+jwt`) | ✅ per-issuance key attestation over the proof keys (`KeyAttestationSource`) — both the `jwt`-proof `key_attestation` header and the `attestation` proof type (Appendix F.3) |

## Detailed coverage & known gaps

Findings of the 2026-07-09 clause-by-clause audit. Unless noted, every gap is symmetric — present
(or absent) in **both** the Kotlin and Swift trees, which remain line-for-line ports of each other.
Only what is 🟡/⬜ is listed; everything else in the tables above verified clean.

### RFC 9901 (SD-JWT)

| Gap | Spec ref | Detail |
|---|---|---|
| `exp`/`nbf` on processed payload | §7.1(6) | 🟡 lives only in the VC layer (`JwtTimeValidator`), not the core `SdJwtVerifier` |
| Holder rejects SD-JWT+KB from Issuer | §7.2 | ✅ `SdJwt.parseFromIssuer` rejects an issuer-delivered SD-JWT that already carries a KB-JWT; enforced in the issuance path, both languages, tested (`parseFromIssuerRejectsSdJwtWithKb`) |
| JWS JSON serialization | §8 (optional) | ⬜ compact only |
| End-to-end RFC vectors | Appendix A | 🟡 RFC vectors cover disclosures only (83 entries); no full issuer-JWT/presentation/KB fixture — E2E tests self-issue |

### SD-JWT VC

| Gap | Spec ref | Detail |
|---|---|---|
| **Type Metadata — all of it** | §4 | ⬜ no vct resolution/retrieval, `extends`, display/rendering (simple or svg_templates), claim metadata, or JSON-schema validation; §4.7 processing never runs in verification |
| `vct#integrity` / `#integrity` | §2.2.2.2, §5 | ⬜ never read or validated |
| Metadata resolver edge cases | §3.1/§3.2 | 🟡 jwks-XOR-jwks_uri not enforced; trailing-`/` in path-bearing `iss` not stripped |
| did-based key resolution | §2.5 (optional) | ⬜ |

### OpenID4VCI 1.0

| Gap | Spec ref | Detail |
|---|---|---|
| `attestation` proof type | Appendix F.3 / §8.2.1 | ✅ `preferAttestationProof` sends a single Key Attestation JWT as `proofs.attestation[0]` (Appendix F.3) — no per-key proof of possession, the `attested_keys` are what the Credential(s) bind to — when the issuer's config lists `attestation` in `proof_types_supported` and a `KeyAttestationSource` is configured; otherwise the `jwt` proof type (attestation in the header). Gated on `CredentialConfiguration.proofTypesSupported` |
| `credential_identifier(s)` issuance flow | §3.4/§6.2/§8.2 | ✅ token-response `authorization_details` parsed into `TokenResponse.credentialIdentifiers` (per config); the Credential Request then sends a `credential_identifier` (never `credential_configuration_id`) when the issuer bound one, else falls back to `credential_configuration_id`. 🟡 a config with **multiple** identifiers requests only the first — the SDK maps a config 1:1 to a credential, so multi-dataset expansion is not done |
| `tx_code` input hints | §4.1.1 | ✅ exposed to the host as `TxCodeSpec` (length / input_mode / description) on `CredentialOffer` and `IssuanceState.TxCodeRequired`; `validate(code)` returns advisory violations. Not enforced by the SDK — the hints are for rendering, and a mismatch is the issuer's call, not ours (headless: no input screen to gate) |
| `mso_mdoc` format | §3.3.1 | 🟡 opaque-string passthrough; live-tested Kotlin only, untested in Swift |

### OpenID4VP 1.0

| Gap | Spec ref | Detail |
|---|---|---|
| DCQL `multiple` | §6.1/§8.1 | ✅ parsed on the credential query; `PresentationSelection` is per-query multi-valued so a `multiple: true` query presents every chosen credential in the vp_token array, and a `multiple: false` query is enforced to exactly one. `auto()` picks all candidates for a `multiple` query, else the first |
| DCQL `trusted_authorities` | §6.1.1, §15.10 | ⬜ not parsed or matched (`aki`, `etsi_tl`, `openid_federation`). Matching is `SHOULD` and the verifier re-validates issuer trust regardless (§6.1), so it is data minimization, not a security boundary |
| DCQL `require_cryptographic_holder_binding` | §6.1 | ✅ parsed (default true). When false the SD-JWT VC is presented without a KB-JWT (`SdJwtHolder.present`), unless `transaction_data` is present (that can only ride in the KB-JWT, so it forces binding). mdoc always binds via DeviceAuth, so the flag is a no-op there |
| Client ID prefixes `verifier_attestation` / `decentralized_identifier` / `openid_federation` | §5.9.3/§12 | ⬜ trust verifier handles x509_san_dns/x509_hash/redirect_uri only |
| `fragment` response mode | §8 | ⬜ rejected as unsupported |
| `transaction_data` | §8.4/B.3.3/B.2.1 | ✅ each entry is parsed and bound to exactly one of its `credential_ids` (§5.1). **SD-JWT VC**: a `sha-256` `transaction_data_hashes` value in the KB-JWT (B.3.3.1). **mdoc**: a device-signed data element (B.2.1) — the host `MdocTransactionDataBinder` supplies the type's (namespace, elementId, value); the wallet device-signs it only after checking the MSO `keyAuthorizations` (§9.1.2.4) authorized it. Rejected with `invalid_transaction_data`: malformed entries, unknown `credential_ids`, a referenced query with `require_cryptographic_holder_binding=false` (B.3.3), a hash-alg set without `sha-256`, an unauthorized/unbindable mdoc element, and (when configured) unsupported `type`s |

### ISO/IEC 18013-5:2021

| Gap | Spec ref | Detail |
|---|---|---|
| Single-purpose mdoc auth key | §9.1.3.4 | 🟡 "A single mdoc authentication key shall not be used to produce both MACs and signatures during its lifetime." Both mechanisms are implemented and selected by `PresentationConfig.mdocDeviceAuth`, but a reused (`KeyUse.Rotate`) DeviceKey can MAC on one channel while signing on another — MAC needs an EReaderKey, which proximity always has and OpenID4VP has only for an encrypted response (unencrypted OID4VP / plain DC API always sign). `KeyUse.OneTime` batch keys satisfy the clause structurally. **Deliberate — see [Deliberate non-goals](#deliberate-non-goals)** |
| NFC negotiated handover | §8.2.2.1/§9.1.5.1 | ✅ (SDK) `MdocNfcEngagement.buildHandoverRequest`/`parseHandoverRequest` + `readerEngagement`; `nfcHandover(hs, hr)` binds `[Hs, Hr]` (static stays `[Hs, null]`, default). Wired through `ProximityService.present` / `ProximityReaderService.read` (`handoverRequestNdef`); negotiated round-trip e2e both languages. **On-wire transport done (Android)**: TNEP over a Type-4 HCE — holder `NfcEngagementProcessor` (static XOR negotiated state machine), reader `MdocNfcHandover` (auto-detects static vs the TNEP Service Select → status → Hr↔Hs dance); pure-Kotlin in `kotlin/proximity` (loopback-tested), thin Android bridge in `android/proximity`. Device-verified two-phone negotiated read (bound `[Hs, Hr]`). No iOS NFC transport (iOS proximity ships BLE only) |
| Session termination | §9.1.1.4 | ✅ holder + reader send the status-20 termination frame after the exchange, destroy the session keys (`SessionEncryption.destroy`), and close; the received `status` is decoded (Table 20 10/11/20). BLE `End` command remains a demo-transport concern |
| BLE / NFC transports | §8.3.3.1 | 🟡 core SDK exposes a transport port only; GATT (both modes, MTU chunking) lives in the **Android demo** and the **iOS `AppleProximity` adapter** (CoreBluetooth, both modes, holder & reader, Ident, chunk pacing); NFC APDU is **Android-only**. **BLE Ident characteristic (§8.3.3.1.1.4) implemented** — SDK `ProximitySessionTranscript.bleIdent` / `DeviceEngagement.eDeviceKeyBytes` (both languages, tested); demo reader (GATT server, central client mode) exposes 00000008, holder (GATT client) reads + verifies (optional/graceful); **verified end-to-end on two devices**. Hardening: `receive`/peer-wait/notify timeouts, connect failure/cancellation cleanup, and **initial-connect retry** (GATT client retries the flaky first `connectGatt` / GATT_ERROR 133, 3× with fresh per-attempt state) — device-verified. No mdoc *session* resumption exists (keys/counters bound to the connection), so a mid-session drop restarts from engagement, by design |
| MSO digest algorithms | §9.1.2.5 | ✅ the reader verifies `valueDigests` under the MSO `digestAlgorithm` — SHA-256, SHA-384 and SHA-512 (Table 21); any other name is rejected. `MdocTestIssuer` can emit each for round-trip + tamper tests |
| Ephemeral-key curves | §9.1.5.2 Table 22 | ✅ P-256, P-384 and P-521 — proximity session keys (`EphemeralKeyPair(curve)`; holder via `PresentationConfig.proximitySessionCurve`, reader matches the mdoc's EDeviceKey curve) and OpenID4VP `direct_post.jwt` / `dc_api.jwt` response encryption (ECDH-ES follows the verifier's chosen curve). No Brainpool / X25519 / X448 |
| `DeviceResponse` errors/status | §8.3.2.1.2.2-.3 | 🟡 a non-zero DeviceResponse **status** (Table 8: 10/11/12 → no documents) is now surfaced on the reader (`MdocReader.verifyDeviceResponse` / `ProximityReaderService.read` throw instead of reporting empty). `documentErrors` / per-document `errors` maps **deliberately not modeled** — mostly ErrorCode 0 ("not returned"), deducible from request↔response; holder still emits `status: 0` + selective-disclosure omission (no error-structure emit) |
| MSO optional fields | §9.1.2.4 | 🟡 `keyAuthorizations` parsed (`nameSpaces` + `dataElements`, used to authorize mdoc `transaction_data` device-signed elements); `expectedUpdate`, `keyInfo` not parsed |
| Wi-Fi Aware · server retrieval (WebAPI/OIDC) | §8.3.3.1.3/§8.3.3.2 (optional) | ⬜ |
| Shared mdoc golden vectors | — | ⬜ `vectors/` covers CBOR/COSE only; cross-language mdoc equivalence rests on round-trip tests + live interop |

### ISO/IEC TS 18013-7:2025

| Gap | Spec ref | Detail |
|---|---|---|
| mdoc MAC auth in OID4VP | B.4.5 | ✅ `HeldMdoc` produces a `deviceMac` when the verifier requests it via `deviceauth_alg_values` (OpenID4VP §B.2.2): the `EMacKey` comes from ECDH between the mdoc `DeviceKey` and the verifier's response-encryption key (the `EReaderKey`, B.4.5), curve-matched, reusing `MdocDeviceAuth.emacKey`. Selection: forced when only MAC is accepted, else the `mdocDeviceAuth` preference (default `deviceSignature`). Needs an encrypted response (no enc key ⇒ signs) |
| Annex B curve set | B.5.2 Table B.8 | 🟡 P-256/384/521 only; no Brainpool / Curve25519/448 (P-256 satisfies the mdoc-side minimum) |
| Verifier-side HPKE decryption | C.4 Table C.3 | ✅ `Hpke.openBaseP256` + `RecipientKey` unseal the `org-iso-mdoc` response — the verifier holds the recipient private key (the `EncryptionInfo.recipientPublicKey` counterpart), decapsulates the KEM secret from `enc`, and AEAD-opens with the SessionTranscript as `info`. Combine with `MdocSessionTranscript.dcApiIsoMdoc` + `MdocReader` for a full reader path |
| Origin abort | C.5 | ✅ a blank origin is rejected before it can bind — both DC API paths (`Request.resolveDcApi`, `MdocSessionTranscript.dcApiIsoMdoc`, the mdoc side citing C.5) |
| Server retrieval | §6.4 | n/a — the TS adds no requirements beyond 18013-5 |

## Deliberate non-goals

Not gaps to be closed later — decisions. Recorded so the matrix cannot be read as a to-do list.

| Item | Spec ref | Why not |
|---|---|---|
| TS-literal `OID4VPHandover` | 18013-7 B.4.4 | The TS predates OpenID4VP 1.0 Final, which replaced the `clientIdHash`/`responseUriHash` + `mdocGeneratedNonce` handover with `OpenID4VPHandover`/`OpenID4VPDCAPIHandover` (jwk-thumbprint form). We implement the Final form, which is what conformant verifiers send — `verifier.eudiw.dev` and `digital-credentials.dev` both interoperate live. Implementing the superseded form would break against them |
| `mdocGeneratedNonce` + the `apu` JWE header | 18013-7 B.4.3.3 / B.5.3 | `apu` is defined as the `mdocGeneratedNonce` *of the B.4.4 SessionTranscript*. With that handover gone there is no such nonce, so `apu` has nothing to carry. (`apv` and `kid` survive — see above) |
| **18013-7 Annex A** — website REST retrieval | Annex A | `RestApiOptions`, HTTP POST `application/cbor`, `OriginInfo`, `EngagementToApp`, `MacKeys`. Out of product scope: the SDK targets proximity (18013-5) and the browser-mediated DC API (Annex C), not a website REST channel |
| Accepting the legacy `vc+sd-jwt` typ | SD-JWT VC §2.2.1 | The only normative rule is "The `typ` value MUST use `dc+sd-jwt`". Accepting the pre-2024-11 name is suggested by a *non-normative* note (lower-case "should", and this draft's RFC 2119 boilerplate makes only upper-case keywords normative). We reject it: the rename was November 2024, nothing in this SDK's ecosystem emits or accepts it (the EUDI reference libraries, Multipaz, and `issuer.eudiw.dev` all use `dc+sd-jwt`), and `typ` exists to prevent type confusion (RFC 8725 §3.11) — every extra accepted value widens that surface for no interop gain. Pinned by `SdJwtVcTypTest` |
| Single-purpose mdoc auth key enforcement | 18013-5 §9.1.3.4 | Both mechanisms shipped; see the 18013-5 table. Accepted as a conformance gap, not a security one |
