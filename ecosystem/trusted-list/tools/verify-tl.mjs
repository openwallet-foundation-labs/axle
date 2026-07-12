// Verifies the generated Trusted List the way a wallet / verifier would: check the JAdES signature against
// the embedded signer cert, confirm §6.8 (signer C == Scheme Territory, O == Scheme operator name), and
// that the list is still fresh (now < nextUpdate). Prints the listed entities.
//   npm run verify:tl
//
// Verified with node crypto rather than jose: JAdES marks `sigT` critical (crit), which jose rejects as an
// unrecognized extension — a JAdES-aware verifier validates the ES256 signature directly instead.
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { X509Certificate, verify as cryptoVerify } from 'node:crypto';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const jades = JSON.parse(readFileSync(join(root, 'public/tl/wallet-providers.jades.json'), 'utf8'));

const header = JSON.parse(Buffer.from(jades.protected, 'base64url').toString());
const signerPem = `-----BEGIN CERTIFICATE-----\n${header.x5c[0]}\n-----END CERTIFICATE-----`;
const cert = new X509Certificate(signerPem);

// JAdES ES256 signature = raw R||S (ieee-p1363) over `${protected}.${payload}`.
const signingInput = Buffer.from(`${jades.protected}.${jades.payload}`);
const sigValid = cryptoVerify('sha256', signingInput, { key: cert.publicKey, dsaEncoding: 'ieee-p1363' }, Buffer.from(jades.signature, 'base64url'));

const lote = JSON.parse(Buffer.from(jades.payload, 'base64url').toString());
const info = lote.listAndSchemeInformation;
const subject = cert.subject.replaceAll('\n', ', ');
const cMatch = new RegExp(`(^|, )C=${info.schemeTerritory}(,|$)`).test(subject);
const oMatch = subject.includes(`O=${info.schemeOperatorName}`);
const fresh = new Date(info.nextUpdate) > new Date();

console.log(sigValid ? '✓ JAdES signature valid (verified against x5c[0])' : '✗ signature INVALID');
console.log('  signer   :', subject);
console.log('  header   :', `alg=${header.alg} sigT=${header.sigT} x5c=${header.x5c.length} x5t#S256=${header['x5t#S256'] ? 'yes' : 'no'} crit=${JSON.stringify(header.crit)}`);
console.log(`  §6.8 bind: C==SchemeTerritory(${info.schemeTerritory}) → ${cMatch} · O==SchemeOperatorName(${info.schemeOperatorName}) → ${oMatch}`);
console.log(`  freshness: now < nextUpdate(${info.nextUpdate.slice(0, 10)}) → ${fresh}`);
console.log('  listed entities:');
for (const e of lote.trustedEntitiesList) {
  for (const s of e.trustedEntityServices) {
    console.log(`    · ${e.trustedEntityInformation.teName}  —  ${s.serviceName}`);
    console.log(`        cert: ${s.serviceDigitalIdentity.x509SubjectName}`);
  }
}
