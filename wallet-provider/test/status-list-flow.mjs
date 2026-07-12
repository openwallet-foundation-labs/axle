// E2E for the Token Status List: WUA carries a status_list ref, the list token decodes, and revoking the
// instance flips its bit. Run against a live backend: `BASE=http://localhost:3200/wp node test/status-list-flow.mjs`
import * as jose from 'jose';
import { inflateSync } from 'node:zlib';

const BASE = process.env.BASE ?? 'http://localhost:3200/wp';
const ISS = process.env.WP_ISSUER ?? BASE;
let ok = true;
const assert = (c, m) => { if (!c) { console.log('❌', m); ok = false; } else console.log('✓', m); };
const adminHeaders = process.env.ADMIN_API_KEY ? { 'x-api-key': process.env.ADMIN_API_KEY } : {};
const post = (p, b) => fetch(`${BASE}${p}`, { method: 'POST', headers: { 'content-type': 'application/json', ...adminHeaders }, body: JSON.stringify(b) });

const statusAt = (lst, bits, idx) => {
  const bytes = inflateSync(Buffer.from(lst.replace(/-/g, '+').replace(/_/g, '/'), 'base64'));
  const entriesPerByte = 8 / bits;
  return (bytes[Math.floor(idx / entriesPerByte)] >> ((idx % entriesPerByte) * bits)) & ((1 << bits) - 1);
};

// 1) register + obtain a WUA
const { nonce } = await (await fetch(`${BASE}/nonce`)).json();
const { publicKey, privateKey } = await jose.generateKeyPair('ES256', { extractable: true });
const instanceJwk = await jose.exportJWK(publicKey);
const reg = await (await post('/wallet-instances', { instanceKey: instanceJwk, integrityToken: `dev-integrity:${nonce}`, nonce })).json();
console.log('registered', reg.instanceId);

const { nonce: popNonce } = await (await fetch(`${BASE}/nonce`)).json();
const pop = await new jose.SignJWT({ nonce: popNonce }).setProtectedHeader({ alg: 'ES256' }).setAudience(ISS).setIssuedAt().sign(privateKey);
const wua = (await (await post('/wallet-attestation', { instanceId: reg.instanceId, pop })).json()).wallet_attestation;

// 2) the WUA references a Token Status List
const ref = jose.decodeJwt(wua).status?.status_list;
assert(ref && Number.isInteger(ref.idx) && typeof ref.uri === 'string', `WUA has status.status_list (idx=${ref?.idx}, uri=${ref?.uri})`);

// 3) fetch + verify the Status List Token
const slResp = await fetch(ref.uri);
assert((slResp.headers.get('content-type') ?? '').includes('application/statuslist+jwt'), 'status list served as application/statuslist+jwt');
const slToken = await slResp.text();
const slHeader = jose.decodeProtectedHeader(slToken);
assert(slHeader.typ === 'statuslist+jwt', 'status list token typ = statuslist+jwt');
const signerPub = await jose.importX509(`-----BEGIN CERTIFICATE-----\n${slHeader.x5c[0]}\n-----END CERTIFICATE-----`, 'ES256');
const { payload } = await jose.jwtVerify(slToken, signerPub);
assert(payload.sub === ref.uri, `status list sub == the WUA's uri (${payload.sub})`);
assert(statusAt(payload.status_list.lst, payload.status_list.bits, ref.idx) === 0, `bit at idx ${ref.idx} = VALID (0) before revoke`);

// 4) revoke the instance → the same bit flips to INVALID
await post(`/wallet-instances/${reg.instanceId}/revoke`, {});
const { payload: p2 } = await jose.jwtVerify(await (await fetch(ref.uri)).text(), signerPub);
assert(statusAt(p2.status_list.lst, p2.status_list.bits, ref.idx) === 1, `bit at idx ${ref.idx} = INVALID (1) after revoke`);

console.log(ok ? '\n✅ STATUS LIST FLOW PASSED' : '\n❌ FAILED');
process.exit(ok ? 0 : 1);
