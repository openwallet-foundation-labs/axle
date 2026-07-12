// Generates the Wallet Provider signing keystore (CA + signer) ONCE. Copy the printed values into your
// deployment secret (raw PEM) or local .env (\n-escaped). Keeping these stable is what lets a WUA issued by
// one replica/boot verify against another — see KeystoreService.
//   cd wallet-provider && node tools/gen-keystore.mjs
import 'reflect-metadata'; // @peculiar/x509 (via tsyringe) needs the reflect polyfill loaded first
import { Crypto } from '@peculiar/webcrypto';
import * as x509 from '@peculiar/x509';

const webcrypto = new Crypto();
x509.cryptoProvider.set(webcrypto);

const alg = { name: 'ECDSA', namedCurve: 'P-256' };
const sigAlg = { name: 'ECDSA', hash: 'SHA-256' };
const validity = { notBefore: new Date('2025-01-01'), notAfter: new Date('2035-01-01') };

const caKeys = await webcrypto.subtle.generateKey(alg, true, ['sign', 'verify']);
const signKeys = await webcrypto.subtle.generateKey(alg, true, ['sign', 'verify']);

const caCert = await x509.X509CertificateGenerator.createSelfSigned({
  serialNumber: '01',
  name: 'CN=EUDI Wallet Provider CA, O=Hopae, C=KR',
  keys: caKeys,
  signingAlgorithm: sigAlg,
  extensions: [
    new x509.BasicConstraintsExtension(true, 1, true),
    new x509.KeyUsagesExtension(x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign, true),
  ],
  ...validity,
});

const signerCert = await x509.X509CertificateGenerator.create({
  serialNumber: '02',
  subject: 'CN=EUDI Wallet Provider Signer, O=Hopae, C=KR',
  issuer: caCert.subject,
  publicKey: signKeys.publicKey,
  signingKey: caKeys.privateKey,
  signingAlgorithm: sigAlg,
  extensions: [
    new x509.BasicConstraintsExtension(false),
    new x509.KeyUsagesExtension(x509.KeyUsageFlags.digitalSignature, true),
  ],
  ...validity,
});

const pkcs8 = Buffer.from(await webcrypto.subtle.exportKey('pkcs8', signKeys.privateKey)).toString('base64');
const norm = (pem) => pem.trim() + '\n';
const signerKeyPem = norm(`-----BEGIN PRIVATE KEY-----\n${pkcs8.match(/.{1,64}/g).join('\n')}\n-----END PRIVATE KEY-----`);
const signerCertPem = norm(signerCert.toString('pem'));
const caCertPem = norm(caCert.toString('pem'));
const esc = (s) => s.replace(/\n/g, '\\n');

console.log('# ─── raw PEM — for a k8s / AWS Secrets Manager multi-line secret ───\n');
console.log('WP_SIGNER_PRIVATE_KEY:\n' + signerKeyPem);
console.log('WP_SIGNER_CERT:\n' + signerCertPem);
console.log('WP_CA_CERT:\n' + caCertPem);
console.log('# ─── single-line \\n-escaped — for .env ───\n');
console.log(`WP_SIGNER_PRIVATE_KEY='${esc(signerKeyPem)}'`);
console.log(`WP_SIGNER_CERT='${esc(signerCertPem)}'`);
console.log(`WP_CA_CERT='${esc(caCertPem)}'`);
