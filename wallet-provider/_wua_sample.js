/* throwaway: print a sample WUA the wallet-provider issues (decoded header/payload + x5c chain). */
require('reflect-metadata');
const jose = require('jose');
const x509 = require('@peculiar/x509');
const { KeystoreService } = require('./dist/src/attestation/keystore.service');
const { AttestationService } = require('./dist/src/attestation/attestation.service');

(async () => {
  const ks = new KeystoreService();
  await ks.onModuleInit();
  const att = new AttestationService(ks);

  // a sample wallet-instance public key (the WUA binds this via cnf.jwk)
  const { publicKey } = await jose.generateKeyPair('ES256', { extractable: true });
  const instanceJwk = await jose.exportJWK(publicKey);

  const wua = await att.issueWalletAttestation(
    instanceJwk,
    'urn:wallet:instance:demo-123',
    { idx: 42, uri: 'https://wallet-provider.hopae.dev/status-list/1' },
  );

  const [h, p] = wua.split('.');
  const header = JSON.parse(Buffer.from(h, 'base64url').toString());
  const payload = JSON.parse(Buffer.from(p, 'base64url').toString());

  console.log('=== COMPACT WUA (truncated) ===');
  console.log(wua.slice(0, 80) + ' … ' + wua.slice(-40));
  console.log('total length:', wua.length, 'chars');

  console.log('\n=== HEADER (x5c abbreviated) ===');
  console.log(JSON.stringify({ ...header, x5c: header.x5c?.map((c, i) => `<cert${i}: ${c.length} b64 chars>`) }, null, 2));
  console.log('x5c present:', Array.isArray(header.x5c), '| certs:', header.x5c?.length);

  console.log('\n=== PAYLOAD ===');
  console.log(JSON.stringify(payload, null, 2));

  console.log('\n=== x5c chain decoded ===');
  header.x5c.forEach((b64, i) => {
    const cert = new x509.X509Certificate(Buffer.from(b64, 'base64'));
    console.log(`  [${i}] subject="${cert.subject}"  issuer="${cert.issuer}"  serial=${cert.serialNumber}`);
  });
})().catch((e) => { console.error(e); process.exit(1); });
