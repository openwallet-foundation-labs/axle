// Builds + JAdES-signs every Trusted List in config/lists/*.json and writes them into public/tl/ (static,
// served by the Vite site / Vercel), plus a lists.json manifest the portal renders. Re-run whenever an entity
// changes or at least every 6 months (Annex E nextUpdate), then commit.
//   npm run gen:tl
import { readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { X509Certificate } from 'node:crypto';
import { buildLote } from './build-lote.mjs';
import { signJades } from './sign-jades.mjs';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');

// Display order for the portal (unknown slugs fall to the end, then alphabetical).
const ORDER = ['wallet-providers', 'pid-issuers', 'attestation-issuers', 'registrar'];
const rank = (slug) => {
  const i = ORDER.indexOf(slug);
  return i === -1 ? ORDER.length : i;
};

let soKeystore;
try {
  soKeystore = JSON.parse(readFileSync(join(root, 'secrets/so-keystore.json'), 'utf8'));
} catch {
  console.error('missing secrets/so-keystore.json — run `npm run gen:so-key` first');
  process.exit(1);
}

const scheme = JSON.parse(readFileSync(join(root, 'config/scheme.json'), 'utf8'));
const lists = readdirSync(join(root, 'config/lists'))
  .filter((f) => f.endsWith('.json'))
  .map((f) => JSON.parse(readFileSync(join(root, 'config/lists', f), 'utf8')))
  .sort((a, b) => rank(a.slug) - rank(b.slug) || a.slug.localeCompare(b.slug));

const at = new Date();
const manifest = { generatedAt: at.toISOString(), lists: [] };

console.log('Trusted Lists generated → public/tl/');
for (const list of lists) {
  const lote = buildLote(root, list, scheme, at);
  const jades = signJades(lote, soKeystore, at);
  const jadesStr = JSON.stringify(jades, null, 2);
  const jws = `${jades.protected}.${jades.payload}.${jades.signature}`; // compact = machine distribution point

  writeFileSync(join(root, `public/tl/${list.slug}.jades.json`), jadesStr + '\n');
  writeFileSync(join(root, `public/tl/${list.slug}.jws`), jws + '\n');

  const info = lote.listAndSchemeInformation;
  manifest.lists.push({
    slug: list.slug,
    title: list.title,
    standard: list.standard,
    description: list.description,
    sequenceNumber: info.loteSequenceNumber,
    issued: info.listIssueDateTime,
    nextUpdate: info.nextUpdate,
    entities: lote.trustedEntitiesList.map((e) => ({
      name: e.trustedEntityInformation.teName,
      services: e.trustedEntityServices.map((s) => s.serviceName),
    })),
    formats: [
      { key: 'jws', label: 'Compact JWS', hint: 'protected.payload.signature', file: `${list.slug}.jws` },
      { key: 'jades.json', label: 'JAdES (JSON)', hint: 'Flattened JWS JSON serialization', file: `${list.slug}.jades.json` },
    ],
  });

  console.log(`  ${list.title}: ${list.slug}.jades.json (${jadesStr.length}B) + .jws · ${lote.trustedEntitiesList.length} entity(ies) · next update ${info.nextUpdate.slice(0, 10)}`);
}

// The Scheme Operator certificate — the trust anchor for EVERY list (also embedded as x5c[0] in each JAdES).
// Published so a verifier can download and pin it (verify the fingerprint out-of-band, then trust the lists).
const soCert = new X509Certificate(soKeystore.certPem);
writeFileSync(join(root, 'public/tl/scheme-operator.pem'), soKeystore.certPem);
manifest.schemeOperator = {
  file: 'scheme-operator.pem',
  subject: soCert.subject.replace(/\n/g, ', '),
  fingerprintSha256: soCert.fingerprint256.replace(/:/g, '').toLowerCase(),
  validTo: soCert.validTo,
};
console.log('  scheme-operator.pem (SO trust anchor)');

// Publish each listed CA certificate so the Document Signers' AIA (caIssuers) URIs resolve at /tl/<ca>.pem.
for (const f of readdirSync(join(root, 'config/certs'))) {
  if (f.endsWith('.pem')) writeFileSync(join(root, 'public/tl', f), readFileSync(join(root, 'config/certs', f)));
}
console.log('  config/certs/*.pem → public/tl/ (CA certs for AIA)');

writeFileSync(join(root, 'public/tl/lists.json'), JSON.stringify(manifest, null, 2) + '\n'); // portal manifest
console.log(`  lists.json (${manifest.lists.length} lists)`);
