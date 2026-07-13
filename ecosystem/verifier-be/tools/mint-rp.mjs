#!/usr/bin/env node
// @ts-check
/**
 * mint-rp.mjs — provision a demo Wallet-Relying Party (WRP) at the RP Registrar and
 * mint the two certificates a verifier needs to authenticate to a wallet:
 *
 *   • WRPAC — Wallet-Relying Party Access Certificate (X.509, ETSI TS 119 411-8).
 *             Presented as the OpenID4VP reader-auth `x5c`; the verifier signs the
 *             Authorization Request with its private key.
 *   • WRPRC — Wallet-Relying Party Registration Certificate (`rc-wrp+jwt` JAdES JWS,
 *             ETSI TS 119 475). Embedded in the request so the wallet can display who
 *             is asking and for what purpose.
 *
 * IMPORTANT KEY-OWNERSHIP FACT (verified against the registrar source):
 *   The registrar does NOT generate the WRPAC keypair and does NOT return a private key.
 *   `POST .../access-certs` takes a caller-supplied PEM EC P-256 *public* key
 *   (AccessCertificateRegistrationDto.publicKey) and OpenSSL signs a leaf cert over it
 *   (`openssl x509 -req -force_pubkey <pub>`). The private key never leaves this script —
 *   we generate it locally below and keep it. This is why the plan works: the verifier
 *   owns the signing key, the registrar only vouches for the public key.
 *
 * The registrar (NestJS, global prefix `/registrar`) exposes:
 *   POST /auth/sign-in                       {email,password}            -> {access_token}
 *   POST /auth/sign-up                        {email,password,name,company} -> {access_token}
 *   POST /portal/wrp                          CreateRelyingPartyDto       -> WalletRelyingParty (has .id)   [Bearer]
 *   POST /portal/wrp/:rpId/access-certs       {publicKey, dns?}           -> {id, crt}                      [Bearer]
 *   POST /portal/wrp/:rpId/registration-certs {support_uri,privacy_policy,purpose?} -> {id, jwt, intendedUse} [Bearer]
 *   GET  /ca-certificate                       -> CA cert PEM  (text)
 *   GET  /ca-certificate.der                   -> CA cert DER  (binary)
 *   GET  /registry/wrp/:rpId/access-certs      -> AccessCertificateEntry[]        (public, unsigned JSON)
 *   GET  /registry/wrp/:rpId/registration-certs-> RegistrationCertificateEntry[]  (public, unsigned JSON)
 *
 * Portal endpoints expect `Authorization: Bearer <access_token>` (JwtGuard, jsonwebtoken HS256, 1y expiry).
 *
 * Usage:
 *   REGISTRAR_URL=https://api.dev.hopae.app/registrar \
 *   REGISTRAR_EMAIL=verifier-dev@hopae.com \
 *   REGISTRAR_PASSWORD='...' \
 *   node tools/mint-rp.mjs > rp-secret.json
 *
 * Output (stdout, single JSON object) is suitable to drop into the verifier's secret:
 *   { rpId, wrpac:{privateKeyPem,certPem,caCertPem,x5c[],sha256Thumbprint}, wrprc, registrarCaPem, registrarCaDerBase64 }
 *
 * Node 20+ only (uses the global `fetch` and `node:crypto`). No external dependencies.
 */

import {
  generateKeyPairSync,
  X509Certificate,
  createHash,
} from 'node:crypto';

// ---------------------------------------------------------------------------
// Configuration (all overridable via env; dev-friendly defaults).
// ---------------------------------------------------------------------------
const BASE = (process.env.REGISTRAR_URL ?? 'https://api.dev.hopae.app/registrar').replace(/\/+$/, '');
const EMAIL = process.env.REGISTRAR_EMAIL ?? 'verifier-dev@hopae.com';
const PASSWORD = process.env.REGISTRAR_PASSWORD ?? 'verifier-dev-password';
const NAME = process.env.REGISTRAR_NAME ?? 'Verifier Dev';
const COMPANY = process.env.REGISTRAR_COMPANY ?? 'Hopae';

// Public URLs advertised by the demo verifier. The registrar embeds these into the WRPRC.
const VERIFIER_ORIGIN = process.env.VERIFIER_ORIGIN ?? 'https://verifier.dev.hopae.app';
const PRIVACY_URI = `${VERIFIER_ORIGIN}/privacy`;
const INFO_URI = VERIFIER_ORIGIN;
const SUPPORT_URI = `${VERIFIER_ORIGIN}/support`;

// ETSI TS 119 475 clause A.2 EU-level entitlement. A verifier is a data *consumer*, i.e. a
// Service Provider. The registrar rejects a WRPRC that carries no known entitlement
// (RegistrationCertService, GEN-5.2.4-03), so this value must come from its ENTITLEMENT_URIS map.
const ENTITLEMENT_SERVICE_PROVIDER = 'https://uri.etsi.org/19475/Entitlement/Service_Provider';

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
    process.stderr.write(`[mint-rp] signed in as ${EMAIL}\n`);
    return access_token;
  } catch (e) {
    // @ts-ignore
    if (e.status !== 401) throw e;
    process.stderr.write(`[mint-rp] sign-in failed (no such user?), signing up ${EMAIL}\n`);
    const { access_token } = await api('POST', '/auth/sign-up', {
      body: { email: EMAIL, password: PASSWORD, name: NAME, company: COMPANY },
    });
    return access_token;
  }
}

/** Create the demo Wallet-Relying Party. Returns the full WalletRelyingParty (with .id). */
async function createRelyingParty(token) {
  // Only fields present on CreateRelyingPartyDto matter (no ValidationPipe strips extras, but keep it clean).
  // Note: `registryURI`, `country` and `intendedUseIdentifier` are assigned by the registrar, not us
  // (country := server WRP_COUNTRY, default 'LU'; registryURI := `/wrp/<uuid>`). `isIntermediary` is
  // forced to false by the controller regardless of what we send.
  const dto = {
    legalName: 'Hopae Demo Verifier',
    tradeName: 'Hopae Demo Verifier',
    // organizationIdentifier of the WRPAC and the WRPRC `sub` are both taken from identifier[0].
    // ETSI TS 119 475 B.2.5: the Identifier object member is `identifier` (not `value`).
    identifier: [{ type: 'LEI', identifier: 'HOPAE-DEMO-VERIFIER-LU-01' }],
    infoURI: [INFO_URI],
    email: EMAIL,
    phone: '+352208000000',
    supportURI: [SUPPORT_URI],
    srvDescription: [
      { lang: 'en', content: 'Hopae demo verifier for EUDI wallet presentations' },
    ],
    isPSB: false, // not a public-sector body
    entitlement: [ENTITLEMENT_SERVICE_PROVIDER],
    supervisoryAuthority: {
      legalName: 'Commission nationale pour la protection des données',
      email: 'info@cnpd.lu',
      phone: '+352261060',
      infoURI: ['https://cnpd.public.lu'],
    },
    // The intended use REGISTERS the credentials/claims this RP will request. The registrar assigns an
    // intendedUseIdentifier (UUID) to it; the wallet can then verify a presentation's requested attributes
    // against this registration via TS5 GET {registryURI}/wrp/check-intended-use (ETSI TS 119 475 B.2.7).
    intendedUse: [
      {
        purpose: [{ lang: 'en', content: 'Age verification' }],
        privacyPolicy: [{ type: 'http://data.europa.eu/eudi/policy/privacy-policy', policyURI: PRIVACY_URI }],
        credential: [
          {
            format: 'mso_mdoc',
            meta: { doctype_value: 'org.iso.18013.5.1.mDL' },
            claim: [['org.iso.18013.5.1', 'given_name'], ['org.iso.18013.5.1', 'family_name'], ['org.iso.18013.5.1', 'birth_date'], ['org.iso.18013.5.1', 'driving_privileges']].map((path) => ({ path })),
          },
          {
            format: 'dc+sd-jwt',
            meta: { vct_values: ['urn:eudi:pid:1'] },
            claim: [['given_name'], ['family_name'], ['age_over_18']].map((path) => ({ path })),
          },
        ],
      },
    ],
    isIntermediary: false,
  };

  const rp = await api('POST', '/portal/wrp', { token, body: dto });
  process.stderr.write(`[mint-rp] created WRP ${rp.id} (intendedUseIdentifier ${rp.intendedUse?.[0]?.intendedUseIdentifier})\n`);
  return rp;
}

/**
 * Build the ETSI TS 119 475 Annex B `registrar_dataset` from the registrar's created RP record — using the
 * REGISTRAR-ASSIGNED intendedUseIdentifier + registryURI (not a hardcoded value), so it matches the
 * registration and the wallet can resolve `${registryURI}/wrp/check-intended-use` against it.
 */
function buildRegistrarDataset(rp) {
  const iu = rp.intendedUse?.[0] ?? {};
  // Map the registrar identifier {type,identifier} to the ETSI dataset shape {type:URI, identifier}.
  const idTypeUri = { LEI: 'http://data.europa.eu/eudi/id/LEI', VAT: 'http://data.europa.eu/eudi/id/VATIN', NTR: 'http://data.europa.eu/eudi/id/EUID' };
  return {
    identifier: (rp.identifier ?? []).map((i) => ({ type: idTypeUri[i.type] ?? i.type, identifier: i.identifier })),
    srvDescription: rp.srvDescription,
    registryURI: rp.registryURI,
    intendedUseIdentifier: iu.intendedUseIdentifier,
    purpose: iu.purpose,
    // 472-2 §5.3.2 CDDL: `policyURI` is a bare URI string (tstr), not an object array.
    policyURI: iu.privacyPolicy?.[0]?.policyURI,
    credential: iu.credential,
  };
}

/**
 * Generate the EC P-256 keypair locally, hand the *public* key to the registrar, and get back the
 * signed WRPAC leaf certificate. The private key stays here.
 * `dns` is optional; it only adds a SAN dNSName for OpenID4VP `x509_san_dns` reader auth. HAIP
 * `x509_hash` needs no SAN at all — it hashes the whole leaf DER — so the cert works either way.
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
  process.stderr.write(`[mint-rp] issued WRPAC serial ${id}\n`);

  return { serial: id, certPem: crt, privateKeyPem };
}

/**
 * Mint the WRPRC (`rc-wrp+jwt` compact JWS). Response is { id, jwt, intendedUse }; the compact JWS
 * string we want is `.jwt`. Most WRPRC content is derived from the RP record; the request supplies the
 * per-issuance bits (support/privacy URIs, purpose) and the `credentials` list — which the registrar
 * embeds verbatim into the WRPRC payload (ETSI TS 119 475 §5.2.4), so it MUST match the registered
 * intendedUse credentials for the wallet's transparency check to line up.
 */
async function issueWrprc(token, rpId, credentials) {
  const res = await api('POST', `/portal/wrp/${rpId}/registration-certs`, {
    token,
    body: {
      support_uri: SUPPORT_URI,
      privacy_policy: PRIVACY_URI,
      purpose: [{ lang: 'en', content: 'Age verification' }],
      credentials,
    },
  });
  process.stderr.write(`[mint-rp] issued WRPRC jti ${res.id}\n`);
  return res.jwt; // compact rc-wrp+jwt JWS string
}

async function main() {
  const token = await authenticate();

  const rp = await createRelyingParty(token);
  const rpId = rp.id;

  const wrpac = await issueWrpac(token, rpId);
  const wrprc = await issueWrprc(token, rpId, rp.intendedUse?.[0]?.credential ?? []);

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
    rpId,
    wrpac: {
      privateKeyPem: wrpac.privateKeyPem,
      certPem: wrpac.certPem,
      caCertPem: registrarCaPem,
      x5c: [leafDerB64, caDerB64],
      sha256Thumbprint,
    },
    wrprc, // compact `rc-wrp+jwt` JWS
    // ETSI TS 119 475 Annex B registrar_dataset with the REGISTRAR-ASSIGNED intendedUseIdentifier +
    // registryURI — drop into the verifier's VERIFIER_REGISTRAR_DATASET.
    registrarDataset: buildRegistrarDataset(rp),
    registrarCaPem,
    registrarCaDerBase64,
  };

  process.stdout.write(JSON.stringify(out, null, 2) + '\n');
}

main().catch((err) => {
  process.stderr.write(`[mint-rp] ERROR: ${err.message}\n`);
  process.exit(1);
});
