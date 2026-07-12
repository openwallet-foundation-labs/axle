// Generates the Scheme Operator (SO) signing keystore — the ROOT of the sandbox trust: the key that signs
// the Trusted Lists. Self-signed; per ETSI TS 119 602 §6.8 the cert's C = Scheme Territory and O = Scheme
// operator name. Written to secrets/so-keystore.json (gitignored) — keep it offline / move to KMS for real.
//   npm run gen:so-key
import 'reflect-metadata';
import { Crypto } from '@peculiar/webcrypto';
import * as x509 from '@peculiar/x509';
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const webcrypto = new Crypto();
x509.cryptoProvider.set(webcrypto);

const scheme = JSON.parse(readFileSync(join(root, 'config/scheme.json'), 'utf8'));
const now = new Date();
const notAfter = new Date(now);
notAfter.setUTCFullYear(notAfter.getUTCFullYear() + 10); // SO signing cert: 10y (the list itself is re-issued <=6mo)

const keys = await webcrypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
const cert = await x509.X509CertificateGenerator.createSelfSigned({
  serialNumber: '01',
  // §6.8: C must equal Scheme Territory, O must equal (one of) Scheme operator name.
  name: `CN=${scheme.schemeOperatorName} Scheme Operator, O=${scheme.schemeOperatorName}, C=${scheme.schemeTerritory}`,
  keys,
  signingAlgorithm: { name: 'ECDSA', hash: 'SHA-256' },
  notBefore: new Date(now.getTime() - 24 * 60 * 60 * 1000),
  notAfter,
  extensions: [
    new x509.BasicConstraintsExtension(false),
    new x509.KeyUsagesExtension(x509.KeyUsageFlags.digitalSignature | x509.KeyUsageFlags.nonRepudiation, true),
    await x509.SubjectKeyIdentifierExtension.create(keys.publicKey),
  ],
});

const pkcs8 = Buffer.from(await webcrypto.subtle.exportKey('pkcs8', keys.privateKey)).toString('base64');
const privateKeyPem = `-----BEGIN PRIVATE KEY-----\n${pkcs8.match(/.{1,64}/g).join('\n')}\n-----END PRIVATE KEY-----\n`;

mkdirSync(join(root, 'secrets'), { recursive: true });
writeFileSync(join(root, 'secrets/so-keystore.json'), JSON.stringify({ privateKeyPem, certPem: cert.toString('pem') + '\n' }, null, 2));
console.log('wrote secrets/so-keystore.json (gitignored)');
console.log('SO signer:', cert.subjectName.toString(), '| valid', now.toISOString().slice(0, 10), '→', notAfter.toISOString().slice(0, 10));
