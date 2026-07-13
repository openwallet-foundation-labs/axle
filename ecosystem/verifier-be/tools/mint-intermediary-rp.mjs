#!/usr/bin/env node
// @ts-check
/**
 * mint-intermediary-rp.mjs — provision an *intermediated* demo Wallet-Relying Party (WRP) at the RP
 * Registrar and mint the two certificates a verifier needs to authenticate to a wallet, but this time
 * the RP operates THROUGH an intermediary. The resulting WRPRC therefore carries the ETSI TS 119 475
 * `intermediary: {sub, sname}` object plus the actor claim `act: {sub}` (GEN-5.2.4-09).
 *
 * This mirrors tools/mint-rp.mjs (the direct / non-intermediated flow); read that file first. The only
 * structural differences are:
 *   1. We first register an *intermediary* WRP (isIntermediary=true) under the same account.
 *   2. The final RP is created as a *mediated* RP under that intermediary. The registrar forces its
 *      `usesIntermediary` link and (when we mint its WRPRC via the intermediary route) stamps the
 *      `intermediary` + `act.sub` claims from the intermediary's registered identifier.
 *
 * IDENTIFIER BINDING (verified against the registrar source — registration_cert.service.ts /
 * access_cert.service.ts / relying_party.service.getUniqueIdentifier):
 *   • The mediated RP's WRPAC `organizationIdentifier` == the mediated RP's identifier[0].value.
 *   • The mediated RP's WRPRC `sub`                     == the mediated RP's identifier[0].value.
 *     → these two are equal, which is exactly the binding the wallet's WRPRCVerifier checks.
 *   • The WRPRC `intermediary.sub` and `act.sub`        == the INTERMEDIARY's identifier[0].value.
 *   The intermediary itself is NEVER issued a WRPRC (Table 7 NOTE 4 — the registrar rejects it); it
 *   only lends its identity to the mediated RP's WRPRC.
 *
 * KEY-OWNERSHIP FACT (unchanged from the direct flow):
 *   The registrar does NOT generate the WRPAC keypair and does NOT return a private key. The mediated
 *   RP's WRPAC is minted through the ordinary `POST /portal/wrp/:rpId/access-certs` route (the
 *   intermediary controllers expose NO mediated-RP access-cert route), which takes a caller-supplied
 *   PEM EC P-256 *public* key and OpenSSL-signs a leaf over it. We generate the keypair locally and
 *   keep the private key — the verifier owns the signing key.
 *
 * The registrar (NestJS, global prefix `/registrar`) exposes for this flow:
 *   POST /auth/sign-in                                                {email,password}                 -> {access_token}
 *   POST /auth/sign-up                                                {email,password,name,company}    -> {access_token}
 *   POST /portal/intermediary                                         CreateRelyingPartyDto            -> WalletRelyingParty (has .id, isIntermediary=true) [Bearer]
 *   POST /portal/intermediary/:id/mediated-rps                        CreateRelyingPartyDto            -> WalletRelyingParty (has .id, usesIntermediary set) [Bearer]
 *   POST /portal/wrp/:rpId/access-certs                               {publicKey, dns?}                -> {id, crt}                                       [Bearer]
 *   POST /portal/intermediary/:id/mediated-rps/:rpId/registration-certs {support_uri,privacy_policy,purpose?} -> {id, jwt, intendedUse}                   [Bearer]
 *   GET  /ca-certificate                                               -> CA cert PEM  (text)
 *   GET  /ca-certificate.der                                           -> CA cert DER  (binary)
 *
 * All portal/intermediary endpoints expect `Authorization: Bearer <access_token>` (JwtGuard, HS256).
 *
 * Usage:
 *   REGISTRAR_URL=https://api.dev.hopae.app/registrar \
 *   REGISTRAR_EMAIL=verifier-dev@hopae.com \
 *   REGISTRAR_PASSWORD='...' \
 *   node tools/mint-intermediary-rp.mjs > intermediary-rp-secret.json
 *
 * Output (stdout, single JSON object) — same shape as mint-rp.mjs plus `intermediaryId`:
 *   { rpId, intermediaryId, wrpac:{privateKeyPem,certPem,caCertPem,x5c[],sha256Thumbprint},
 *     wrprc, registrarCaPem, registrarCaDerBase64 }
 *   (`rpId` is the MEDIATED RP; `intermediaryId` is the intermediary WRP it operates through.)
 *
 * Node 20+ only (uses the global `fetch` and `node:crypto`). No external dependencies.
 */

import {
  generateKeyPairSync,
  X509Certificate,
  createHash,
} from 'node:crypto';

// ---------------------------------------------------------------------------
// Configuration (all overridable via env; dev-friendly defaults matching mint-rp.mjs).
// ---------------------------------------------------------------------------
const BASE = (process.env.REGISTRAR_URL ?? 'https://api.dev.hopae.app/registrar').replace(/\/+$/, '');
const EMAIL = process.env.REGISTRAR_EMAIL ?? 'verifier-dev@hopae.com';
const PASSWORD = process.env.REGISTRAR_PASSWORD ?? 'verifier-dev-password';
const NAME = process.env.REGISTRAR_NAME ?? 'Verifier Dev';
const COMPANY = process.env.REGISTRAR_COMPANY ?? 'Hopae';

// Public URLs advertised by the demo *mediated* verifier (the final RP). Embedded into its WRPRC.
const VERIFIER_ORIGIN = process.env.VERIFIER_ORIGIN ?? 'https://verifier.dev.hopae.app';
const PRIVACY_URI = `${VERIFIER_ORIGIN}/privacy`;
const INFO_URI = VERIFIER_ORIGIN;
const SUPPORT_URI = `${VERIFIER_ORIGIN}/support`;

// Public URLs advertised by the demo intermediary itself.
const INTERMEDIARY_ORIGIN = process.env.INTERMEDIARY_ORIGIN ?? 'https://intermediary.dev.hopae.app';

// ETSI TS 119 475 clause A.2 EU-level entitlement. Both the intermediary and the mediated RP are data
// *consumers*, i.e. Service Providers. The registrar rejects a WRPRC that carries no known entitlement
// (RegistrationCertService, GEN-5.2.4-03), so the mediated RP MUST carry this from ENTITLEMENT_URIS.
const ENTITLEMENT_SERVICE_PROVIDER = 'https://uri.etsi.org/19475/Entitlement/Service_Provider';

// Registered semantic identifiers. These become the WRPAC organizationIdentifier / WRPRC sub (mediated
// RP) and the WRPRC intermediary.sub / act.sub (intermediary). They MUST differ so the two roles are
// distinguishable in the minted WRPRC.
const MEDIATED_IDENTIFIER = process.env.MEDIATED_RP_IDENTIFIER ?? 'HOPAE-DEMO-MEDIATED-RP-LU-01';
const INTERMEDIARY_IDENTIFIER = process.env.INTERMEDIARY_IDENTIFIER ?? 'HOPAE-DEMO-INTERMEDIARY-LU-01';

// ---------------------------------------------------------------------------
// Tiny HTTP helper. Prints the response body on any non-2xx so failures are debuggable.
// ---------------------------------------------------------------------------

/**
 * @param {string} method
 * @param {string} path            path under the registrar base, e.g. '/auth/sign-in'
 * @param {{ token?: string, body?: unknown, accept?: string }} [opts]
 * @returns {Promise<any>}         parsed JSON, or raw text if the response isn't JSON
 */
async function api(method, path, opts = {}) {
  const { token, body, accept } = opts;
  const headers = {};
  if (token) headers['Authorization'] = `Bearer ${token}`;
  if (accept) headers['Accept'] = accept;
  if (body !== undefined) headers['Content-Type'] = 'application/json';

  const res = await fetch(`${BASE}${path}`, {
    method,
    headers,
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });

  const text = await res.text();
  if (!res.ok) {
    // Surface the server's error body — NestJS returns { statusCode, message, error }.
    const err = new Error(`${method} ${path} -> ${res.status} ${res.statusText}\n${text}`);
    // @ts-ignore attach status for control flow (sign-in 401 -> sign-up)
    err.status = res.status;
    throw err;
  }

  const ct = res.headers.get('content-type') ?? '';
  if (ct.includes('application/json')) {
    return text ? JSON.parse(text) : undefined;
  }
  return text; // e.g. ca-certificate PEM (text/x-pem-file)
}

/** Fetch a binary body and return it as a base64 string (for ca-certificate.der). */
async function apiBinaryBase64(path) {
  const res = await fetch(`${BASE}${path}`);
  const buf = Buffer.from(await res.arrayBuffer());
  if (!res.ok) {
    throw new Error(`GET ${path} -> ${res.status} ${res.statusText}\n${buf.toString('utf8')}`);
  }
  return buf.toString('base64');
}

/** Strip PEM armor/whitespace -> the base64 DER body, which is exactly an RFC 7515 x5c entry. */
function pemToDerBase64(pem) {
  return pem
    .replace(/-----BEGIN CERTIFICATE-----/g, '')
    .replace(/-----END CERTIFICATE-----/g, '')
    .replace(/\s+/g, '');
}

// ---------------------------------------------------------------------------
// Flow.
// ---------------------------------------------------------------------------

/** Sign in; if the account doesn't exist yet (401), sign up. Returns the JWT access token. */
async function authenticate() {
  try {
    const { access_token } = await api('POST', '/auth/sign-in', {
      body: { email: EMAIL, password: PASSWORD },
    });
    process.stderr.write(`[mint-int-rp] signed in as ${EMAIL}\n`);
    return access_token;
  } catch (e) {
    // @ts-ignore
    if (e.status !== 401) throw e;
    process.stderr.write(`[mint-int-rp] sign-in failed (no such user?), signing up ${EMAIL}\n`);
    const { access_token } = await api('POST', '/auth/sign-up', {
      body: { email: EMAIL, password: PASSWORD, name: NAME, company: COMPANY },
    });
    return access_token;
  }
}

/**
 * Register the demo intermediary WRP. The controller forces `isIntermediary = true`. The intermediary
 * is never issued a WRPRC; it only contributes its identifier[0].value + tradeName to the mediated RP's
 * WRPRC (as intermediary.sub / act.sub / intermediary.sname). Returns the full WalletRelyingParty.
 */
async function createIntermediary(token) {
  const dto = {
    legalName: 'Hopae Demo Intermediary',
    tradeName: 'Hopae Demo Intermediary',
    // identifier[0].value -> WRPRC intermediary.sub / act.sub on the mediated RP's registration cert.
    identifier: [{ type: 'LEI', value: INTERMEDIARY_IDENTIFIER }],
    infoURI: [INTERMEDIARY_ORIGIN],
    email: EMAIL,
    phone: '+352208000001',
    supportURI: [`${INTERMEDIARY_ORIGIN}/support`],
    srvDescription: [
      { lang: 'en', content: 'Hopae demo intermediary for EUDI wallet presentations' },
    ],
    isPSB: false,
    entitlement: [ENTITLEMENT_SERVICE_PROVIDER],
    supervisoryAuthority: {
      legalName: 'Commission nationale pour la protection des données',
      email: 'info@cnpd.lu',
      phone: '+352261060',
      infoURI: ['https://cnpd.public.lu'],
    },
    // isIntermediary is forced true by the controller regardless of what we send.
    isIntermediary: true,
  };

  const intermediary = await api('POST', '/portal/intermediary', { token, body: dto });
  process.stderr.write(`[mint-int-rp] created intermediary ${intermediary.id}\n`);
  return intermediary;
}

/**
 * Register the demo mediated Relying Party under the intermediary. The controller forces
 * `isIntermediary = false` and stamps `usesIntermediary` from the intermediary record, so we only send
 * the ordinary RP fields. Returns the full WalletRelyingParty (with .id).
 */
async function createMediatedRP(token, intermediaryId) {
  const dto = {
    legalName: 'Hopae Demo Mediated RP',
    tradeName: 'Hopae Demo Mediated RP',
    // identifier[0].value -> the mediated RP's WRPAC organizationIdentifier AND its WRPRC `sub`
    // (both come from getUniqueIdentifier(rp)); this is the binding the wallet's WRPRCVerifier checks.
    identifier: [{ type: 'LEI', value: MEDIATED_IDENTIFIER }],
    infoURI: [INFO_URI],
    email: EMAIL,
    phone: '+352208000000',
    supportURI: [SUPPORT_URI],
    srvDescription: [
      { lang: 'en', content: 'Hopae demo mediated verifier for EUDI wallet presentations' },
    ],
    isPSB: false, // not a public-sector body
    // Country is server-assigned (WRP_COUNTRY, default 'LU'); CreateRelyingPartyDto carries no country
    // field, so the mediated RP lands in LU by the registrar's config.
    entitlement: [ENTITLEMENT_SERVICE_PROVIDER],
    supervisoryAuthority: {
      legalName: 'Commission nationale pour la protection des données',
      email: 'info@cnpd.lu',
      phone: '+352261060',
      infoURI: ['https://cnpd.public.lu'],
    },
    intendedUse: [
      {
        purpose: [{ lang: 'en', content: 'Age verification' }],
        privacyPolicy: [{ type: 'url', uri: PRIVACY_URI }],
        credential: [],
      },
    ],
    // usesIntermediary + isIntermediary=false are forced by the controller from the intermediary record.
    isIntermediary: false,
  };

  const rp = await api('POST', `/portal/intermediary/${intermediaryId}/mediated-rps`, {
    token,
    body: dto,
  });
  process.stderr.write(`[mint-int-rp] created mediated RP ${rp.id} under intermediary ${intermediaryId}\n`);
  return rp;
}

/**
 * Generate the EC P-256 keypair locally, hand the *public* key to the registrar, and get back the signed
 * WRPAC leaf certificate for the MEDIATED RP. The private key stays here. There is no mediated-RP access
 * -cert route on the intermediary controllers, so we use the ordinary `POST /portal/wrp/:rpId/access-certs`
 * with the mediated RP's id — its subject.organizationIdentifier is the mediated RP's identifier[0].value.
 * `dns` only adds a SAN dNSName for OpenID4VP `x509_san_dns`; HAIP `x509_hash` needs no SAN.
 */
async function issueWrpac(token, rpId) {
  const { publicKey, privateKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const publicKeyPem = publicKey.export({ type: 'spki', format: 'pem' }).toString();
  const privateKeyPem = privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();

  // Response shape: { id: <serial>, crt: <leaf PEM> }. Leaf only — no chain is returned.
  const { id, crt } = await api('POST', `/portal/wrp/${rpId}/access-certs`, {
    token,
    body: {
      publicKey: publicKeyPem,
      dns: [new URL(VERIFIER_ORIGIN).hostname],
    },
  });
  process.stderr.write(`[mint-int-rp] issued mediated-RP WRPAC serial ${id}\n`);

  return { serial: id, certPem: crt, privateKeyPem };
}

/**
 * Mint the mediated RP's WRPRC (`rc-wrp+jwt` compact JWS) through the INTERMEDIARY route. Because we go
 * via `/portal/intermediary/:id/mediated-rps/:rpId/registration-certs`, the service sets
 * `dto.intermediary = <intermediaryId>` server-side, which makes the payload carry
 * `intermediary: {sub, sname}` and `act: {sub}` derived from the intermediary's identifier[0].value.
 * Response is { id, jwt, intendedUse }; the compact JWS string we want is `.jwt`.
 */
async function issueWrprc(token, intermediaryId, rpId) {
  const res = await api(
    'POST',
    `/portal/intermediary/${intermediaryId}/mediated-rps/${rpId}/registration-certs`,
    {
      token,
      body: {
        support_uri: SUPPORT_URI,
        privacy_policy: PRIVACY_URI,
        purpose: [{ lang: 'en', content: 'Age verification' }],
      },
    },
  );
  process.stderr.write(`[mint-int-rp] issued mediated-RP WRPRC jti ${res.id} (intermediary populated)\n`);
  return res.jwt; // compact rc-wrp+jwt JWS string
}

async function main() {
  const token = await authenticate();

  const intermediary = await createIntermediary(token);
  const intermediaryId = intermediary.id;

  const rp = await createMediatedRP(token, intermediaryId);
  const rpId = rp.id;

  const wrpac = await issueWrpac(token, rpId);
  const wrprc = await issueWrprc(token, intermediaryId, rpId);

  // Registrar CA (trust anchor) in both encodings.
  const registrarCaPem = (await api('GET', '/ca-certificate', { accept: 'application/x-pem-file' })).trim();
  const registrarCaDerBase64 = await apiBinaryBase64('/ca-certificate.der');

  // Build the reader-auth chain. x5c = [leaf, CA] as base64 DER (RFC 7515 §4.1.6, NOT base64url).
  const leafDerB64 = pemToDerBase64(wrpac.certPem);
  const caDerB64 = pemToDerBase64(registrarCaPem);

  // SHA-256 of the leaf DER (hex). HAIP `x509_hash` is the base64url of this same digest.
  const leafDer = new X509Certificate(wrpac.certPem).raw; // DER bytes
  const sha256Thumbprint = createHash('sha256').update(leafDer).digest('hex');

  const out = {
    rpId, // the MEDIATED RP (WRPRC sub / WRPAC organizationIdentifier)
    intermediaryId, // the intermediary it operates through (WRPRC intermediary.sub / act.sub)
    wrpac: {
      privateKeyPem: wrpac.privateKeyPem,
      certPem: wrpac.certPem,
      caCertPem: registrarCaPem,
      x5c: [leafDerB64, caDerB64],
      sha256Thumbprint,
    },
    wrprc, // compact `rc-wrp+jwt` JWS (carries intermediary + act.sub)
    registrarCaPem,
    registrarCaDerBase64,
  };

  process.stdout.write(JSON.stringify(out, null, 2) + '\n');
}

main().catch((err) => {
  process.stderr.write(`[mint-int-rp] ERROR: ${err.message}\n`);
  process.exit(1);
});
