// Generates a self-signed issuer CA (trust anchor) for the sandbox — a root the issued credentials chain to.
// Profiled as an ISO/IEC 18013-5 Annex B IACA root (Table B.1): CSPRNG serial, CA:TRUE pathLen=0, KeyUsage
// keyCertSign+cRLSign, SKI, issuerAltName (contact URI) and a CRL distribution point. The PUBLIC cert goes to
// config/certs/<slug>.pem (committed, listed in the Trusted List); the private key to secrets/<slug>.json.
//   node tools/gen-issuer-ca.mjs <slug> "<CN suffix>"
//   e.g. node tools/gen-issuer-ca.mjs pid-issuer-ca "PID Issuer CA"
import 'reflect-metadata';
import { Crypto } from '@peculiar/webcrypto';
import * as x509 from '@peculiar/x509';
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { csprngSerial, issuerAltNameUri, crlDistributionPointUri } from './cert-ext.mjs';

const [slug, cnSuffix] = process.argv.slice(2);
if (!slug || !cnSuffix) {
  console.error('usage: node tools/gen-issuer-ca.mjs <slug> "<CN suffix>"');
  process.exit(1);
}

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const webcrypto = new Crypto();
x509.cryptoProvider.set(webcrypto);

const scheme = JSON.parse(readFileSync(join(root, 'config/scheme.json'), 'utf8'));
const base = (scheme.siteUrl || 'https://trusted-list.vercel.app').replace(/\/$/, '');

const now = new Date();
const notAfter = new Date(now);
notAfter.setUTCFullYear(notAfter.getUTCFullYear() + 10); // IACA root: 10y (Table B.1 allows up to 20y)

const keys = await webcrypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
const cert = await x509.X509CertificateGenerator.createSelfSigned({
  serialNumber: csprngSerial(),
  // EN 319 412-1 organizationIdentifier (2.5.4.97) + legal person; C = issuing country (LU).
  name: `CN=Hopae S.A. ${cnSuffix}, 2.5.4.97=NTRLU-B000000, O=Hopae S.A., C=LU`,
  keys,
  signingAlgorithm: { name: 'ECDSA', hash: 'SHA-256' },
  notBefore: new Date(now.getTime() - 24 * 60 * 60 * 1000),
  notAfter,
  extensions: [
    new x509.BasicConstraintsExtension(true, 0, true), // CA:TRUE, pathLenConstraint=0, critical
    new x509.KeyUsagesExtension(x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign, true),
    await x509.SubjectKeyIdentifierExtension.create(keys.publicKey),
    issuerAltNameUri(`${base}/`), // Annex B: contact for the IACA
    crlDistributionPointUri(`${base}/crl/${slug}.crl`),
  ],
});

const pkcs8 = Buffer.from(await webcrypto.subtle.exportKey('pkcs8', keys.privateKey)).toString('base64');
const privateKeyPem = `-----BEGIN PRIVATE KEY-----\n${pkcs8.match(/.{1,64}/g).join('\n')}\n-----END PRIVATE KEY-----\n`;
const certPem = cert.toString('pem') + '\n';

mkdirSync(join(root, 'secrets'), { recursive: true });
mkdirSync(join(root, 'config/certs'), { recursive: true });
writeFileSync(join(root, `secrets/${slug}.json`), JSON.stringify({ privateKeyPem, certPem }, null, 2));
writeFileSync(join(root, `config/certs/${slug}.pem`), certPem);

console.log(`wrote config/certs/${slug}.pem (public) + secrets/${slug}.json (private, gitignored)`);
console.log('IACA:', cert.subjectName.toString(), '| valid', now.toISOString().slice(0, 10), '→', notAfter.toISOString().slice(0, 10));
