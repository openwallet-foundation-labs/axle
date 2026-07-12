// End-to-end exercise of the Wallet Provider: nonce -> register -> PoP -> WUA -> verify -> key attestation.
import * as jose from 'jose';

const BASE = process.env.BASE ?? 'http://localhost:3200/wp';
const ISS = process.env.WP_ISSUER ?? BASE; // the instance-PoP audience = the backend's WP_ISSUER
const adminHeaders = process.env.ADMIN_API_KEY ? { 'x-api-key': process.env.ADMIN_API_KEY } : {};
const post = (path, body) =>
  fetch(`${BASE}${path}`, { method: 'POST', headers: { 'content-type': 'application/json', ...adminHeaders }, body: JSON.stringify(body) });
const assert = (cond, msg) => { if (!cond) throw new Error(`assertion failed: ${msg}`); };

async function main() {
  // 1) challenge + wallet instance key
  const { nonce } = await (await fetch(`${BASE}/nonce`)).json();
  const { publicKey, privateKey } = await jose.generateKeyPair('ES256', { extractable: true });
  const instanceJwk = await jose.exportJWK(publicKey);

  // 2) register instance (dev integrity token)
  const reg = await (await post('/wallet-instances', { instanceKey: instanceJwk, integrityToken: `dev-integrity:${nonce}`, nonce })).json();
  assert(reg.instanceId, 'instanceId returned');
  console.log('registered:', reg.instanceId);

  // 3) PoP over a fresh nonce, signed by the instance key
  const { nonce: popNonce } = await (await fetch(`${BASE}/nonce`)).json();
  const pop = await new jose.SignJWT({ nonce: popNonce })
    .setProtectedHeader({ typ: 'oauth-client-attestation-pop+jwt', alg: 'ES256' })
    .setAudience(ISS).setIssuedAt().sign(privateKey);

  // 4) obtain the WUA
  const wuaResp = await (await post('/wallet-attestation', { instanceId: reg.instanceId, pop })).json();
  assert(wuaResp.wallet_attestation, 'WUA returned');
  const wua = wuaResp.wallet_attestation;

  // 5) verify the WUA: header, x5c, signature, cnf binding
  const header = jose.decodeProtectedHeader(wua);
  assert(header.typ === 'oauth-client-attestation+jwt', 'WUA typ');
  assert(Array.isArray(header.x5c) && header.x5c.length === 2, 'x5c = [signer, CA]');
  const signerPub = await jose.importX509(`-----BEGIN CERTIFICATE-----\n${header.x5c[0]}\n-----END CERTIFICATE-----`, 'ES256');
  const { payload } = await jose.jwtVerify(wua, signerPub, { issuer: ISS });
  // JWK key order is insignificant (jsonb round-trips do not preserve it), so compare canonically.
  const canon = (o) => JSON.stringify(Object.keys(o).sort().reduce((a, k) => ((a[k] = o[k]), a), {}));
  assert(canon(payload.cnf.jwk) === canon(instanceJwk), 'cnf.jwk binds the instance key');
  console.log(`WUA verified: iss=${payload.iss} sub=${payload.sub} aal=${payload.aal}`);

  // 6) PoP replay must fail (nonce single-use)
  const replay = await post('/wallet-attestation', { instanceId: reg.instanceId, pop });
  assert(replay.status >= 400, 'PoP replay rejected');
  console.log('replay rejected:', replay.status);

  // 7) key attestation (issuer c_nonce passed through)
  const { publicKey: credPub } = await jose.generateKeyPair('ES256', { extractable: true });
  const credJwk = await jose.exportJWK(credPub);
  const kaResp = await (await post('/key-attestation', { attestedKeys: [credJwk], nonce: 'c-nonce-xyz' })).json();
  const kaHeader = jose.decodeProtectedHeader(kaResp.key_attestation);
  const kaPub = await jose.importX509(`-----BEGIN CERTIFICATE-----\n${kaHeader.x5c[0]}\n-----END CERTIFICATE-----`, 'ES256');
  const { payload: ka } = await jose.jwtVerify(kaResp.key_attestation, kaPub, { issuer: ISS });
  assert(kaHeader.typ === 'keyattestation+jwt', 'key attestation typ');
  assert(ka.nonce === 'c-nonce-xyz' && Array.isArray(ka.attested_keys), 'key attestation binds keys + nonce');
  console.log('key attestation verified: attested_keys=%d nonce=%s', ka.attested_keys.length, ka.nonce);

  // 8) revoke -> status reflects it -> further WUA issuance rejected
  const rev = await post(`/wallet-instances/${reg.instanceId}/revoke`, {});
  assert(rev.status < 300, 'revoke accepted');
  const st = await (await fetch(`${BASE}/wallet-instances/${reg.instanceId}/status`)).json();
  assert(st.revoked === true && st.revokedAt, 'status shows revoked');
  const { nonce: n3 } = await (await fetch(`${BASE}/nonce`)).json();
  const pop2 = await new jose.SignJWT({ nonce: n3 })
    .setProtectedHeader({ typ: 'oauth-client-attestation-pop+jwt', alg: 'ES256' })
    .setAudience(ISS).setIssuedAt().sign(privateKey);
  const afterRevoke = await post('/wallet-attestation', { instanceId: reg.instanceId, pop: pop2 });
  assert(afterRevoke.status === 401, 'revoked instance cannot obtain a WUA');
  console.log('revocation: status.revoked=%s, post-revoke WUA rejected=%d', st.revoked, afterRevoke.status);

  console.log('\n✅ ALL WALLET PROVIDER FLOWS PASSED (persisted + revocation)');
}
main().catch((e) => { console.error('❌', e.message); process.exit(1); });
