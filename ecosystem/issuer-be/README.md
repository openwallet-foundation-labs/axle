# EUDI Issuer — backend

OpenID4VCI 1.0 + HAIP credential issuer. Issues **PID as SD-JWT VC and as mdoc** (authorization-code flow) and
**mDL as mdoc** (pre-authorized-code flow). NestJS + Fastify, mirrors `wallet-provider` (pino/Prometheus/
terminus, Drizzle + Postgres, Redis, env-loaded signing keys). Claims are hardcoded (sandbox demo).

Everything is served under the **`/eudi-issuer`** prefix; the credential issuer identifier is
`${origin}/eudi-issuer`. Metadata sits at the origin root per RFC 8414.

## Endpoints

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/.well-known/openid-credential-issuer/eudi-issuer` | Credential issuer metadata (OID4VCI 1.0) |
| GET | `/.well-known/oauth-authorization-server/eudi-issuer` | Authorization server metadata (RFC 8414) |
| GET | `/eudi-issuer/jwks.json` | Issuer signing JWKS |
| POST | `/eudi-issuer/par` | Pushed Authorization Request (wallet-attestation client auth) |
| GET | `/eudi-issuer/authorize` | → redirects the browser to **issuer-fe** for the issuance consent |
| GET/POST | `/eudi-issuer/interaction/:id[/decide]` | consent handshake with issuer-fe |
| POST | `/eudi-issuer/credential-offer/create` · GET `/credential-offer/:id` | pre-authorized offer (mDL) |
| POST | `/eudi-issuer/token` | token endpoint (auth-code + pre-auth grants; DPoP-bound) |
| POST | `/eudi-issuer/nonce` | c_nonce endpoint |
| POST | `/eudi-issuer/credential` | credential endpoint (proof + key attestation → credential) |
| GET | `/eudi-issuer/status-lists/:id` · POST `/status-lists/revoke` | Token Status List token / revoke |

## Security

- **DPoP** (RFC 9449) on token + credential, with the server-nonce challenge.
- **Wallet Attestation / WUA** (HAIP §4.4.1): the `oauth-client-attestation` JWT's `x5c` must chain to a
  Wallet Provider CA published in the Trusted List (`TRUSTED_LIST_URL`, fetched + JAdES-verified + cached).
- **Key Attestation** (HAIP §4.5.1) at the credential endpoint.
- `DEV_ATTESTATION_BYPASS=true` accepts wallets without attestations (local dev only).
- Signing keys are the **Document Signers** minted from the ecosystem CAs
  (`ecosystem/trusted-list/tools/gen-signer.mjs`), loaded via `ISSUER_PID_SIGNER` / `ISSUER_MDL_SIGNER`.

## Run locally

```bash
cp .env.example .env            # then paste the two signer JSONs (from trusted-list/secrets)
# Postgres + Redis running; then:
pnpm install
pnpm build && pnpm migrate      # apply drizzle migrations
pnpm start:prod                 # or: pnpm start:dev
```

## Deploy

Container is built by the `Dockerfile` (same shape as `wallet-provider`); run `node dist/migrate` as a
migration Job/init-container, then `node dist/main`. The k8s manifests live in the separate infra repo (as
with wallet-provider). Set `ISSUER_BASE_URL`, `ISSUER_FE_URL`, `DATABASE_URL`, `REDIS_URL`, the two signer
secrets, and unset `DEV_ATTESTATION_BYPASS`.

## Known limitations

- **mdoc status list**: SD-JWT VC credentials carry the `status.status_list` reference, but mdoc (PID/mDL)
  do not — `@lukas.j.han/mdoc` 0.5.11 (latest) has no MSO `status` element (ISO/IEC 18013-5 2nd edition).
  The issuance is still recorded in the status list; embedding the mdoc reference is deferred until the
  library supports the MSO `status` field. mdoc currently relies on `validityInfo` (expiry).

## Standards

OpenID4VCI 1.0 · OpenID4VC HAIP 1.0 · IETF SD-JWT VC · ISO/IEC 18013-5 mdoc · IETF Token Status List ·
RFC 9449 (DPoP) · RFC 9126 (PAR) · RFC 7636 (PKCE). Sandbox — not a production issuer.
