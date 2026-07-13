// Mints a leaf Document Signer (DSC) certificate signed by one of the issuer CAs — the key the Issuer backend
// actually signs credentials with (SD-JWT VC x5c[0] / mdoc x5chain[0]). Per HAIP the leaf is NOT self-signed
// and the trust anchor (the CA) is NOT included; verifiers resolve the CA from the published Trusted List.
//
// Profiled per credential family:
//   pid  — ETSI TS 119 412-6 §4: qcStatement id-etsi-qct-pid  (PID; SD-JWT VC + mdoc)
//   mdl  — ISO/IEC 18013-5 Annex B DS cert: EKU id-mdl-kp-mdlDS (critical) + ETSI §6 id-etsi-qct-eaa, ≤457d
// Both get: CSPRNG serial, KeyUsage digitalSignature, SKI, AKI, AIA (caIssuers), CRL distribution point.
//   node tools/gen-signer.mjs <ca-slug> <signer-slug> "<CN suffix>" <pid|mdl>
import 'reflect-metadata';
import { Crypto } from '@peculiar/webcrypto';
import * as x509 from '@peculiar/x509';
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import {
  OID,
  csprngSerial,
  qcStatementsExtension,
  crlDistributionPointUri,
  authorityInfoAccessCaIssuers,
} from './cert-ext.mjs';

const [caSlug, signerSlug, cnSuffix, profile] = process.argv.slice(2);
if (!caSlug || !signerSlug || !cnSuffix || !['pid', 'mdl', 'access'].includes(profile)) {
  console.error('usage: node tools/gen-signer.mjs <ca-slug> <signer-slug> "<CN suffix>" <pid|mdl|access>');
  process.exit(1);
}

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const webcrypto = new Crypto();
x509.cryptoProvider.set(webcrypto);

const scheme = JSON.parse(readFileSync(join(root, 'config/scheme.json'), 'utf8'));
const base = (scheme.siteUrl || 'https://trusted-list.vercel.app').replace(/\/$/, '');

const ca = JSON.parse(readFileSync(join(root, `secrets/${caSlug}.json`), 'utf8'));
const caCert = new x509.X509Certificate(ca.certPem);
const caKey = await webcrypto.subtle.importKey(
  'pkcs8',
  Buffer.from(ca.privateKeyPem.replace(/-----[^-]+-----|\s/g, ''), 'base64'),
  { name: 'ECDSA', namedCurve: 'P-256' },
  false,
  ['sign'],
);

const now = new Date();
const notAfter = new Date(now);
if (profile === 'mdl') notAfter.setUTCDate(notAfter.getUTCDate() + 457); // ISO 18013-5 Annex B: max notBefore+457d
else notAfter.setUTCFullYear(notAfter.getUTCFullYear() + 3); // PID (412-6) / access: 3y

// Family-specific extensions.
//   pid    — id-etsi-qct-pid QcType (PID DSC)
//   mdl    — id-mdl-kp-mdlDS EKU, no QcType (§6 EAA)
//   access — the PID/EAA Provider's ACCESS certificate that signs the (signed) Issuer Metadata JWS
//            (ETSI TS 119 472-3 ISS-MDATA-4.2.1-02). It is NOT a Document Signer, so it carries no
//            credential-signing QcType/EKU — just the base leaf extensions below.
const familyExts =
  profile === 'mdl'
    ? [new x509.ExtendedKeyUsageExtension([OID.mdlDS], true)] // §6 EAA defers to EN 319 412-2/-3 — NO QcType
    : profile === 'access'
      ? []
      : [qcStatementsExtension(OID.qctPid)];

const keys = await webcrypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
const cert = await x509.X509CertificateGenerator.create({
  serialNumber: csprngSerial(),
  subject: `CN=Hopae S.A. ${cnSuffix}, 2.5.4.97=NTRLU-B000000, O=Hopae S.A., C=LU`,
  issuer: caCert.subject,
  notBefore: new Date(now.getTime() - 24 * 60 * 60 * 1000),
  notAfter,
  publicKey: keys.publicKey,
  signingKey: caKey,
  signingAlgorithm: { name: 'ECDSA', hash: 'SHA-256' },
  extensions: [
    new x509.BasicConstraintsExtension(false, undefined, true), // CA:FALSE
    new x509.KeyUsagesExtension(x509.KeyUsageFlags.digitalSignature, true),
    await x509.SubjectKeyIdentifierExtension.create(keys.publicKey),
    await x509.AuthorityKeyIdentifierExtension.create(caCert),
    authorityInfoAccessCaIssuers(`${base}/tl/${caSlug}.pem`),
    crlDistributionPointUri(`${base}/crl/${signerSlug}.crl`),
    ...familyExts,
  ],
});

const pkcs8 = Buffer.from(await webcrypto.subtle.exportKey('pkcs8', keys.privateKey)).toString('base64');
const privateKeyPem = `-----BEGIN PRIVATE KEY-----\n${pkcs8.match(/.{1,64}/g).join('\n')}\n-----END PRIVATE KEY-----\n`;

mkdirSync(join(root, 'secrets'), { recursive: true });
writeFileSync(
  join(root, `secrets/${signerSlug}.json`),
  JSON.stringify({ privateKeyPem, certPem: cert.toString('pem') + '\n', caCertPem: ca.certPem }, null, 2),
);

console.log(`wrote secrets/${signerSlug}.json (${profile} profile)`);
console.log('DSC   :', cert.subjectName.toString());
console.log('issuer:', caCert.subjectName.toString(), '| valid', now.toISOString().slice(0, 10), '→', notAfter.toISOString().slice(0, 10));
