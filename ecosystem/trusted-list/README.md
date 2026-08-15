# Trusted List — Scheme Operator

Builds + JAdES-signs the sandbox's ETSI TS 119 602 Trusted Lists and serves them as a static site.

**Live:** https://trusted-list.vercel.app

## Layout

```
config/
  scheme.json          shared Scheme Operator info + siteUrl (distribution-point origin)
  lists/*.json         one file per Trusted List: loteType, scheme name, entities, cert refs
  certs/*.pem          public CA certificates listed in the lists (the trust anchors)
  certs/mdl-iaca/*.pem mirrored real-world mDL / ID-Pass IACA roots (see below)
tools/
  gen-so-keystore.mjs  mint the Scheme Operator signing key   → secrets/so-keystore.json
  gen-issuer-ca.mjs    mint an issuer/attestation CA           → config/certs + secrets/
  build-lote.mjs       config → ETSI TS 119 602 LoTE object
  sign-jades.mjs       LoTE  → JAdES (ETSI TS 119 182-1, Baseline-B)
  gen-tl.mjs           sign every list → public/tl/ + lists.json manifest
  verify-tl.mjs        verify every generated list
public/tl/             generated signed lists (.jws + .jades.json) + lists.json  (served at /tl)
src/                   Vite + shadcn/ui portal (reads /tl/lists.json)
```

## Regenerate & deploy (no CI — done by hand)

```bash
# one-time: the Scheme Operator root that signs every list (kept offline)
npm run gen:so-key

# one-time per issuer/attestation CA (public cert committed, private key gitignored)
node tools/gen-issuer-ca.mjs pid-issuer-ca  "PID Issuer CA"
node tools/gen-issuer-ca.mjs attestation-ca "Attestation Issuer CA (mDL)"
# (registrar-ca.pem is reused from the registrar-be CA — public cert only)

npm run gen:tl      # build + JAdES-sign all config/lists/*.json → public/tl/
npm run verify:tl   # check every list: signature, §6.8 binding, freshness
git commit … && git push   # Vercel deploys the static site
```

## Add a Trusted List

1. Drop the trust anchor's public cert in `config/certs/<name>.pem`.
2. Add `config/lists/<slug>.json` (`slug`, `title`, `standard`, `description`, `loteType`, `schemeName`,
   `entities[]` referencing the cert).
3. `npm run gen:tl && npm run verify:tl`, commit, push. The portal picks it up from `lists.json` — no app
   code change.

## Mirrored real-world IACAs

`attestation-issuers` carries two kinds of entity, told apart by `serviceTypeIdentifier`:

| | `serviceTypeIdentifier` | Meaning |
| --- | --- | --- |
| Scheme-certified | `http://uri.etsi.org/19602/SvcType/…` | The Attestation Issuer CA this sandbox operates |
| **Mirrored** | `…/svctype/EAA/Issuance/{mDL,PhotoID}/mirrored-iaca` | A production issuing authority root observed from its public source and republished |

The mirrored entries are the US state mDL IACA roots plus the Apple / Google ID-Pass roots, so the sandbox
verifier and the demo reader can verify **real** credentials from Apple Wallet, Google Wallet and the state
wallets. The Scheme Operator does not certify, audit or supervise a mirrored entity — it only republishes a
certificate it observed. In a production ecosystem these belong in an ISO/IEC 18013-5 Annex C **VICAL**, not
in a scheme LoTE; this is a sandbox shortcut, tracked as such.

Adding or rotating one: drop the PEM in `config/certs/mdl-iaca/`, add a service to that authority's entity in
`config/lists/attestation-issuers.json` (`serviceName` carries the CN + expiry), bump `loteSequenceNumber`,
then regenerate, verify, commit and push as above. Consumers need no code change — `verifier-be` re-reads the
list every 15 min, the demo wallet every 24 h.

Superseded roots stay listed while credentials signed under them are still in the field; expired ones are
dropped (the importer refuses to register a cert past `notAfter`).

## Develop

```bash
npm run dev       # Vite dev server
npm run build     # typecheck + production build → dist/
```

`VITE_SITE_URL` (`.env` / Vercel env) sets the origin shown in the `curl` commands; download links stay
relative so any deployment works. Deploy on Vercel with **Root Directory = `ecosystem/trusted-list`**
(`vercel.json` sets the build, output and media types).

## Standards

ETSI TS 119 602 (List of Trusted Entities) · ETSI TS 119 182-1 (JAdES) · EUDI ARF trust model.
Signed with [`@lukas.j.han/jades`](https://www.npmjs.com/package/@lukas.j.han/jades). Sandbox — not a
production trust list.
