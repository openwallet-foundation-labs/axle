// One-glance inventory of every sandbox key. Reads the offline vault (secrets/, gitignored), prints each
// key's role, fingerprint, validity and chain, and cross-checks it against what's published (config/certs +
// the live Trusted List) and deployed (the running Wallet Provider). Never prints private keys.
//   node tools/keys-status.mjs
import { readFileSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { X509Certificate } from 'node:crypto';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const S = (p) => join(root, p);
const load = (f) => (existsSync(S(`secrets/${f}`)) ? JSON.parse(readFileSync(S(`secrets/${f}`), 'utf8')) : null);
const cert = (pem) => (pem ? new X509Certificate(pem) : null);
const fp = (c) => c.fingerprint256.replace(/:/g, '').toLowerCase().slice(0, 12);
const day = (d) => new Date(d).toISOString().slice(0, 10);
const pub = (f) => (existsSync(S(f)) ? new X509Certificate(readFileSync(S(f), 'utf8')) : null);

// role, keystore file, which PEM is the primary cert, (optional) issuing CA PEM, published copy, deploy target.
const VAULT = [
  { role: 'Scheme Operator (signs every Trusted List)', file: 'so-keystore.json', main: 'certPem' },
  { role: 'Wallet Provider CA (WUA trust anchor)', file: 'wp-keystore.json', main: 'caCertPem', published: 'config/certs/wp-ca.pem', deploy: 'AWS hopae/dev/wp/app-secrets → wp-api' },
  { role: '└ WUA signer (WP signs wallet attestations)', file: 'wp-keystore.json', main: 'certPem', issuer: 'caCertPem' },
  { role: 'PID Issuer CA (PID trust anchor)', file: 'pid-issuer-ca.json', main: 'certPem', published: 'config/certs/pid-issuer-ca.pem' },
  { role: '└ PID Document Signer (issuer signs PID)', file: 'pid-signer.json', main: 'certPem', issuer: 'caCertPem', deploy: 'issuer env ISSUER_PID_SIGNER' },
  { role: 'Attestation/mDL Issuer CA (mDL anchor)', file: 'attestation-ca.json', main: 'certPem', published: 'config/certs/attestation-ca.pem' },
  { role: '└ mDL Document Signer (issuer signs mDL)', file: 'mdl-signer.json', main: 'certPem', issuer: 'caCertPem', deploy: 'issuer env ISSUER_MDL_SIGNER' },
];

console.log('\nSANDBOX KEY VAULT  ·  ecosystem/trusted-list/secrets/  (offline, gitignored)\n');
for (const e of VAULT) {
  const ks = load(e.file);
  if (!ks) {
    console.log(`✗ ${e.role}\n    MISSING: secrets/${e.file}\n`);
    continue;
  }
  const c = cert(ks[e.main]);
  const flags = [];
  if (e.published) {
    const p = pub(e.published);
    flags.push(p && fp(p) === fp(c) ? `published✓ (${e.published})` : `published✗ MISMATCH (${e.published})`);
  }
  if (e.issuer) {
    const ca = cert(ks[e.issuer]);
    flags.push(c.checkIssued(ca) ? 'chains✓' : 'chains✗ BROKEN');
  }
  const expiring = new Date(c.validTo) < new Date(Date.now() + 90 * 864e5);
  console.log(`${e.role}`);
  console.log(`    ${e.file} · sha256 ${fp(c)}… · valid ${day(c.validFrom)}→${day(c.validTo)}${expiring ? ' ⚠EXPIRING' : ''}`);
  console.log(`    ${c.subject.replace(/\n/g, ', ')}`);
  if (flags.length) console.log(`    ${flags.join('  ·  ')}`);
  if (e.deploy) console.log(`    deploy: ${e.deploy}`);
  console.log();
}

// Live cross-checks (best-effort; skip on network failure).
const short = (h) => h.slice(0, 12);
async function liveChecks() {
  const wpCa = cert(load('wp-keystore.json')?.caCertPem);
  const soCert = cert(load('so-keystore.json')?.certPem);
  console.log('LIVE CROSS-CHECKS');
  try {
    const j = await (await fetch('https://trusted-list.vercel.app/tl/wallet-providers.jades.json', { signal: AbortSignal.timeout(8000) })).json();
    const hdr = JSON.parse(Buffer.from(j.protected, 'base64url').toString());
    const soLive = new X509Certificate(`-----BEGIN CERTIFICATE-----\n${hdr.x5c[0]}\n-----END CERTIFICATE-----`);
    const lote = JSON.parse(Buffer.from(j.payload, 'base64url').toString());
    const wpLive = new X509Certificate(Buffer.from(lote.trustedEntitiesList[0].trustedEntityServices[0].serviceDigitalIdentity.x509Certificate, 'base64'));
    console.log(`    Trusted List signed by SO   : ${fp(soLive) === fp(soCert) ? '✓ matches vault SO' : '✗ MISMATCH'} (${short(fp(soLive))}…)`);
    console.log(`    Trusted List publishes WP CA: ${fp(wpLive) === fp(wpCa) ? '✓ matches vault WP CA' : '✗ MISMATCH'} (${short(fp(wpLive))}…)`);
  } catch (e) {
    console.log(`    (trusted list unreachable: ${e.message})`);
  }
  try {
    const pem = await (await fetch('https://dev.api.hopae.com/wp/.well-known/wallet-provider-ca.pem', { signal: AbortSignal.timeout(8000) })).text();
    const served = new X509Certificate(pem);
    console.log(`    Deployed WP serves CA       : ${fp(served) === fp(wpCa) ? '✓ matches vault WP CA' : '✗ MISMATCH'} (${short(fp(served))}…)`);
  } catch (e) {
    console.log(`    (deployed WP unreachable: ${e.message})`);
  }
  console.log();
}
await liveChecks();
