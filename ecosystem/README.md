# Hopae EUDI Sandbox — Ecosystem

A standards-conformant, self-operated sandbox for the EU Digital Identity Wallet (EUDI). Every trust
relationship is anchored in X.509 certificates and published as ETSI-standard, JAdES-signed **Trusted Lists**
— so wallets, issuers and verifiers can establish trust the same way they would in the real eIDAS ecosystem.

## Live sandbox

Every counterpart the wallet talks to, hosted and reachable:

| Service | URL | Role |
|---|---|---|
| **PID Issuer** | https://pid-issuer.vercel.app/ | OpenID4VCI — issue PID (SD-JWT VC & mdoc) + mDL |
| **Verifier** | https://eudi-verifier.vercel.app/ | OpenID4VP + DC API — request & verify presentations |
| **RP Registrar** | https://demo-registrar.vercel.app/ | Register relying parties; issue WRPAC/WRPRC (separate repo) |
| **Trusted List** | https://trusted-list.vercel.app/ | Scheme Operator — JAdES-signed trust lists |

## Trusted List portal — https://trusted-list.vercel.app

The Scheme Operator (**Hopae**) publishes the Trusted Lists of the entities in the sandbox. Each list is a
[ETSI TS 119 602](https://www.etsi.org/standards) *List of Trusted Entities* (LoTE), signed as
[ETSI TS 119 182-1](https://www.etsi.org/standards) **JAdES** (Baseline-B). Verifiers download the signed
list for a service type — compact JWS or JAdES JSON — or fetch it with `curl`.

| List | Trust anchor it publishes | Credentials / use | Standard |
| --- | --- | --- | --- |
| **Wallet Providers** | WP CA that wallet-unit attestations (WUAs) chain to | Axle Wallet | ETSI TS 119 602 Annex E |
| **PID Issuers** | PID Issuer CA | PID — SD-JWT VC + mdoc | EUDI ARF (PID Providers) |
| **Attestation Issuers** | Attestation Issuer CA | mDL — mdoc (ISO/IEC 18013-5) | EUDI ARF ((Q)EAA Providers) |
| **Registrar** | Registrar CA relying-party access certs chain to | RP registration | EUDI ARF (Registration) |

Every list is signed by the Hopae **Scheme Operator** key (self-signed root; per ETSI TS 119 602 §6.8 the
signer's `C` = Scheme Territory = `EU` and `O` = Scheme operator = `Hopae`). Signatures are ES256 with the
claimed signing time (`sigT`) critical and the signing certificate bound both by value (`x5c`) and by
reference (`x5t#S256`).

## Trust model

```
Scheme Operator (Hopae, C=EU)  ──signs──▶  Trusted Lists (JAdES)
                                              │  each list publishes a trust anchor:
   Wallet Providers list  ──▶ WP CA           ├─▶ wallet-unit attestations (WUAs) chain to WP CA
   PID Issuers list       ──▶ PID Issuer CA   ├─▶ PID (SD-JWT VC / mdoc) chain to PID Issuer CA
   Attestation list       ──▶ Attestation CA  ├─▶ mDL (mdoc) chains to Attestation CA
   Registrar list         ──▶ Registrar CA    └─▶ relying-party access certs chain to Registrar CA
```

A verifier trusts a credential by: fetching the relevant signed list → checking the JAdES signature against
the Scheme Operator → then checking the credential's certificate chains to a CA on that list.

## Components

- [`trusted-list/`](./trusted-list) — the Scheme Operator: builds + JAdES-signs the Trusted Lists and serves
  them as a static site (Vite + shadcn/ui, deployed to Vercel). Also mints the ecosystem CAs and Document
  Signers (`tools/gen-issuer-ca.mjs`, `tools/gen-signer.mjs`).
- [`issuer-be/`](./issuer-be) — the credential Issuer: OpenID4VCI 1.0 + HAIP backend issuing PID (SD-JWT VC +
  mdoc, authorization-code flow) and mDL (mdoc, pre-authorized-code flow). NestJS + Fastify + Postgres, DPoP,
  Wallet/Key Attestation (WUA verified against the Trusted List), Token Status List.
- [`issuer-fe/`](./issuer-fe) — the issuance consent screen for the authorization-code flow (Vite + React,
  European eID styling, "issue this PID to your wallet").
- [`verifier-be/`](./verifier-be) — the relying party: OpenID4VP 1.0 + HAIP backend that builds & verifies
  presentations over QR (`request_uri` + `direct_post`) and the W3C Digital Credentials API, with WRPAC-signed
  requests, encrypted responses, and Token Status List revocation checks.
- [`verifier-fe/`](./verifier-fe) — the relying-party UI: create a request (QR / DC API), then show the
  verified claims + trust status (Vite + React).

The **Wallet Provider** (WUA + key attestation) lives at the repo root in [`../wallet-provider`](../wallet-provider),
and the **RP Registrar** is a separate project at
[github.com/hopae-official/registrar](https://github.com/hopae-official/registrar)
(sandbox at https://demo-registrar.vercel.app/).

## Roadmap

- [x] **P1** Scheme Operator + Trusted Lists (wallet providers, PID issuers, attestation issuers, registrar)
- [x] **P2** Issuer — OpenID4VCI 1.0 + HAIP: PID (SD-JWT VC + mdoc) via authorization-code, mDL (mdoc) via
  pre-authorized-code; DPoP, Wallet/Key Attestation, Token Status List (`issuer-be` + `issuer-fe`)
- [x] **P3** Verifier (relying party) — OpenID4VP 1.0 + HAIP over QR + DC API (`verifier-be` + `verifier-fe`)
- [x] **P4** Registrar — RP registration + WRPAC/WRPRC (ETSI TS 119 475; separate service)

## Security

The Scheme Operator signing key and the issuer CA private keys are held offline
(`trusted-list/secrets/`, gitignored — move to KMS/HSM for anything beyond the sandbox). Lists are re-issued
at least every 6 months (Annex E `nextUpdate`).

## Development notes

### Verifying changes (project convention)

- **Don't verify with local NestJS builds/servers.** The loop is: `npx tsc --noEmit` per service +
  standalone Node checks against the service's `node_modules` (e.g. issue-and-parse an mdoc directly
  with `@lukas.j.han/mdoc`), then deploy to the dev cluster and verify live.
- Images are tagged with the **SDK repo commit SHA** (ECR tags are immutable — never re-tag): issuer
  `<sha>`, verifier `<sha>-verifierNN`. Build with `docker build --platform linux/amd64`.
- Runtime config lives in AWS Secrets Manager (one JSON secret per service) synced by
  External Secrets: `put-secret-value` → annotate the ExternalSecret with `force-sync` → rollout.

### Certificate profiles — test against ALL verifier stacks

The sandbox Document Signers / CAs (minted by `trusted-list/tools/gen-signer.mjs`, keys under
`trusted-list/secrets/`, map in `KEYS.md`) are consumed by three X.509 stacks with different
strictness: **Java PKIX (kotlin), Node, and swift-certificates (iOS)**. swift-certificates rejects
any chain carrying a *critical* extension no verifier policy handles — a spec-required critical EKU
on the mDL DS broke iOS while Android/Node stayed green. **After any cert-profile change (especially
critical extensions), run the fixture harness**:
`issuer-be/tools/gen-mdoc-fixtures.ts` → `swift test --filter LiveIssuerFixtureTests`
(see `swift/README.md`).

Related: the mdoc library truncates MSO `ValidityInfo` tdates to whole seconds (ISO 18013-5 forbids
fractional seconds) — don't rely on millisecond precision; third-party issuers may still emit
fractional tdates, which the wallets accept leniently.

### Adding a credential type end-to-end (checklist)

1. `issuer-be/src/vci/credential-configs.ts` — new `CredentialConfig` (metadata/consent/issuance all
   derive from it). New DSC only if it must chain to a different CA.
2. `verifier-be/src/vp/dcql.ts` — `RequestableKey` + `REQUESTABLE` entry; `verifier-fe` card + the
   ISO-mdoc gate.
3. **Re-mint the RP registration** — `verifier-be/tools/mint-rp.mjs` + `mint-intermediary-rp.mjs`
   must register the new credential/claims (RPRC_21), then update the verifier secret
   (`VERIFIER_WRPAC/WRPRC/REGISTRAR_DATASET` + `_INTERMEDIARY`) — otherwise wallets flag the request
   "out of registration scope". Registrar gotchas: re-minting creates a NEW RP (delete stale RPs with
   the same identifier — `check-intended-use` matches the first); its `claimpath` query param is a
   single path element, not a JSON array.
4. iOS: add the doctype to `demo-ios/.../AxleWallet.entitlements` (DC API routing) — see
   `ios/README.md`. Android needs nothing (registration is store-driven).
5. Demo cosmetics: `CredentialVisuals` (both platforms), issuer-fe `DESCRIPTIONS`, reader
   `ReaderDocKind` if it should be requestable in person.
