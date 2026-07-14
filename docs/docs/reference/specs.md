---
id: specs
title: Specifications
sidebar_position: 99
---

# Specifications

The exact source specifications this SDK implements, grouped by standards body. Each entry gives the
title and version as tracked by the project, a one-line note on **what the SDK uses it for**, and a
link to the **official public source** (not a local copy).

For a clause-level, version-pinned view of coverage — which version of each spec is implemented, what
is partial, and the known gaps — see **`SPEC-MATRIX.md` at the repository root** (it lives outside this
docs site, so it is not linked here).

Access notes: **ISO/IEC** documents are **paywalled** (only the catalogue page is public). **ETSI**,
**OpenID Foundation**, **IETF/RFC**, and **EU** documents are freely downloadable.

---

## ISO/IEC

Mobile document (mdoc) data model, proximity retrieval, and online presentation.

- **ISO/IEC 18013-5:2021 — Mobile driving licence (mDL) application** — The mdoc data model the SDK's
  `mdoc` / `MDoc` and `proximity` modules implement: `IssuerSigned`/MSO, `DeviceResponse`, selective
  disclosure, device authentication (signature and MAC), reader authentication, and §9 device retrieval
  (QR/NFC engagement, BLE session crypto). [ISO catalogue 69084](https://www.iso.org/standard/69084.html)
- **ISO/IEC TS 18013-7:2025 — mDL add-on functions** — Online/browser-mediated presentation of an mdoc:
  the origin-bound `SessionTranscript` and HPKE-sealed `org-iso-mdoc` response for the Digital
  Credentials API (Annex C); Annex B handover aligned to OpenID4VP 1.0 Final.
  [ISO catalogue 91154](https://www.iso.org/standard/91154.html)
- **ISO/IEC 23220-1:2023 — Generic system architectures of mobile eID systems** — Reference architecture
  and lifecycle model underpinning the mdoc building blocks. [ISO catalogue 74910](https://www.iso.org/standard/74910.html)
- **ISO/IEC DTS 23220-2 (Draft, final text 2024-02-28) — Data objects and encoding rules for generic eID
  systems** — The generic CBOR data model / encoding rules the mdoc structures build on. Local reference
  copy is the DTS draft text; the published Technical Specification is
  [ISO catalogue 86782](https://www.iso.org/standard/86782.html).
- **ISO/IEC TS 23220-3 (Working Draft WD13) — Issuing phase** — Reference for the credential
  issuance/provisioning phase of mobile eID systems. Under development — search "ISO/IEC 23220-3" at
  [iso.org](https://www.iso.org/) (paywalled).
- **ISO/IEC 23220-4 (Draft, pre-RC5 consultation) — Operational phase** — Reference for the operational
  (presentation) phase of mobile eID systems. Under development — search "ISO/IEC 23220-4" at
  [iso.org](https://www.iso.org/) (paywalled).
- **ISO/IEC 7367 (Working Draft WD2) — Mobile documents** — The mdoc generalization (mobile documents /
  mVC) beyond the mDL. Under development — search "ISO/IEC 7367" at [iso.org](https://www.iso.org/)
  (paywalled).

---

## ETSI

eIDAS 2.0 trust framework: certificate profiles, relying-party attributes, and trusted lists. All are
free to download from the [ETSI standards search](https://www.etsi.org/standards-search).

- **ETSI TR 119 462 v1.1.1 — Wallet interfaces for trust services** — Informative reference for the
  wallet-to-trust-service-provider interfaces. [ETSI standards search](https://www.etsi.org/standards-search#page=1&search=119%20462)
- **ETSI TS 119 411-8 v1.1.1 — Access certificate policy for wallet relying parties** — Certificate
  policy for the Wallet Relying Party Access Certificate (WRPAC) that the SDK's trust/registrar path
  validates. [ETSI standards search](https://www.etsi.org/standards-search#page=1&search=119%20411-8)
- **ETSI TS 119 412-6 v1.2.1 — Certificate profile for PID, Wallet and (Q)EAA providers** — The X.509
  certificate profile (`id-etsi-qct-wal`) used for the SDK's issuer and Wallet Unit Attestation signer
  certificates. [ETSI standards search](https://www.etsi.org/standards-search#page=1&search=119%20412-6)
- **ETSI TS 119 461 v2.1.1 — Identity proofing** — Identity-proofing requirements for wallet onboarding
  (informative reference for the ecosystem). [ETSI standards search](https://www.etsi.org/standards-search#page=1&search=119%20461)
- **ETSI TS 119 471 v1.1.1 — (Q)EAA provider policy** — Policy and security requirements for (Q)EAA
  providers (issuer-side reference). [ETSI standards search](https://www.etsi.org/standards-search#page=1&search=119%20471)
- **ETSI TS 119 472-1 v1.2.1 — EAA profiles: general** — General attestation profile requirements shared
  across issuance and presentation. [ETSI standards search](https://www.etsi.org/standards-search#page=1&search=119%20472-1)
- **ETSI TS 119 472-2 v1.2.1 — EAA profiles: presentation** — Defines the WRPRC transport as a
  `registration_cert` object carried in OpenID4VP `verifier_info`; consumed by the SDK's presentation
  trust path. [ETSI standards search](https://www.etsi.org/standards-search#page=1&search=119%20472-2)
- **ETSI TS 119 472-3 v1.1.1 — EAA/PID issuance profiles** — Attestation profile requirements specific to
  issuance. [ETSI standards search](https://www.etsi.org/standards-search#page=1&search=119%20472-3)
- **ETSI TS 119 475 v1.2.1 — Relying party attributes** — The relying-party registration attribute set
  carried in the WRPRC dataset and checked by the SDK's `WRPRCVerifier`. [ETSI standards search](https://www.etsi.org/standards-search#page=1&search=119%20475)
- **ETSI TS 119 602 v1.1.1 — Trusted lists data model** — The trusted-list data model backing the SDK's
  `TrustConfig` anchors (issuer and registrar trusted lists). [ETSI standards search](https://www.etsi.org/standards-search#page=1&search=119%20602)

---

## OpenID Foundation

Issuance and presentation protocols. All are free to read.

- **OpenID for Verifiable Credential Issuance (OpenID4VCI) 1.0** — Issuance protocol implemented by the
  `openid4vci` module (pre-authorized and authorization-code flows, PAR, signed metadata, encrypted
  requests/responses, deferred issuance, key-proof mechanisms). [openid.net](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html)
- **OpenID for Verifiable Presentations (OpenID4VP) 1.0** — Presentation protocol implemented by the
  `openid4vp` module (DCQL engine, JAR request resolution, `vp_token`, `direct_post`/`direct_post.jwt`,
  DC API, transaction data). [openid.net](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html)
- **OpenID4VC High Assurance Interoperability Profile (HAIP) 1.0** — The interoperability profile pinning
  the mandatory subset (PAR/DPoP/PKCE, wallet & key attestation, batch, signed metadata) the SDK
  conforms to. [openid.net](https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-1_0.html)

---

## IETF

Credential formats, status, and OAuth building blocks. All are free to read.

- **RFC 9901 — Selective Disclosure for JSON Web Tokens (SD-JWT)** — The core selective-disclosure JWT
  the `sdjwt` / `SdJwt` module implements (issue/present/verify, KB-JWT, decoys). [rfc-editor.org](https://www.rfc-editor.org/rfc/rfc9901)
- **draft-ietf-oauth-sd-jwt-vc (SD-JWT VC)** — The SD-JWT-based verifiable credential format enforced by
  `SdJwtVcVerifier` (typ/iss/vct, holder binding, status extraction). [datatracker.ietf.org](https://datatracker.ietf.org/doc/draft-ietf-oauth-sd-jwt-vc/)
- **draft-ietf-oauth-status-list (Token Status List)** — The status/revocation mechanism the `statuslist`
  / `StatusList` module fetches and verifies. [datatracker.ietf.org](https://datatracker.ietf.org/doc/draft-ietf-oauth-status-list/)

Also used by the SDK (issuance / OAuth layer):

- **RFC 9449 — OAuth 2.0 Demonstrating Proof of Possession (DPoP)** — Sender-constrained access tokens
  during issuance. [rfc-editor.org](https://www.rfc-editor.org/rfc/rfc9449)
- **RFC 9126 — OAuth 2.0 Pushed Authorization Requests (PAR)** — Pushed authorization requests in the
  authorization-code issuance flow. [rfc-editor.org](https://www.rfc-editor.org/rfc/rfc9126)
- **RFC 7636 — Proof Key for Code Exchange (PKCE, S256)** — Authorization-code protection during
  issuance. [rfc-editor.org](https://www.rfc-editor.org/rfc/rfc7636)

Formats & crypto (implemented per `SPEC-MATRIX.md`, no PDF in the reference set):

- **RFC 8949 — CBOR** (deterministic encoding). [rfc-editor.org](https://www.rfc-editor.org/rfc/rfc8949)
- **RFC 9052 / 9053 / 9360 — COSE** (`COSE_Sign1`, algorithms, x5chain). [9052](https://www.rfc-editor.org/rfc/rfc9052) · [9053](https://www.rfc-editor.org/rfc/rfc9053) · [9360](https://www.rfc-editor.org/rfc/rfc9360)
- **RFC 7515 / 7518 — JOSE (JWS / JWE)** (compact ES256/384/512, ECDH-ES + A*GCM). [7515](https://www.rfc-editor.org/rfc/rfc7515) · [7518](https://www.rfc-editor.org/rfc/rfc7518)
- **RFC 9180 — HPKE** (base mode; seals the DC API `org-iso-mdoc` response). [rfc-editor.org](https://www.rfc-editor.org/rfc/rfc9180)
- **RFC 5280 — X.509 PKIX** (chain validation in the `trust` / `Trust` module). [rfc-editor.org](https://www.rfc-editor.org/rfc/rfc5280)

---

## EU / eIDAS

The legal and architectural framework the wallet targets.

- **EU Digital Identity Wallet — Architecture and Reference Framework (ARF)** — The reference
  architecture and technical requirements the SDK's ecosystem is built to. [GitHub](https://github.com/eu-digital-identity-wallet/eudi-doc-architecture-and-reference-framework)
- **Regulation (EU) 2024/1183 (eIDAS 2.0)** — Amends Regulation (EU) No 910/2014; the legal basis for the
  European Digital Identity Wallet. [EUR-Lex](https://eur-lex.europa.eu/eli/reg/2024/1183/oj)
