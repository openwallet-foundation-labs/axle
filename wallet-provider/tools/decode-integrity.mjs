// Dev tool: decode a Google Play Integrity token and print the verdict. No secrets here — it reads the
// service account from GOOGLE_SERVICE_ACCOUNT_JSON (a JSON string, same secret the backend uses) or falls
// back to GOOGLE_APPLICATION_CREDENTIALS / ADC, and the app id from PLAY_INTEGRITY_PACKAGE_NAME.
//
//   cd wallet-provider
//   GOOGLE_SERVICE_ACCOUNT_JSON="$(cat /path/to/service-account.json)" \
//   PLAY_INTEGRITY_PACKAGE_NAME=com.hopae.axle.wallet \
//   node tools/decode-integrity.mjs "<integrity-token>"
//
// The token comes from the client's IntegrityManager.requestIntegrityToken (see PlayIntegrityTokenProvider);
// it is short-lived, so decode promptly. This is exactly what the backend IntegrityService.verifyPlayIntegrity
// does — handy for eyeballing the raw appIntegrity / deviceIntegrity / accountDetails verdicts.
import { GoogleAuth } from 'google-auth-library';
import { readFileSync } from 'fs';

const pkg = process.env.PLAY_INTEGRITY_PACKAGE_NAME || 'com.hopae.axle.wallet';
let token = process.argv[2] || '';
const asFile = (p) => { try { return readFileSync(p, 'utf8').trim(); } catch { return null; } };
if (token && token.length < 300) token = asFile(token) || token; // allow a file path
if (!token) { console.error('usage: node tools/decode-integrity.mjs <token|tokenFile>'); process.exit(1); }

const saJson = process.env.GOOGLE_SERVICE_ACCOUNT_JSON;
const auth = new GoogleAuth({
  scopes: ['https://www.googleapis.com/auth/playintegrity'],
  ...(saJson ? { credentials: JSON.parse(saJson) } : {}),
});
const accessToken = await (await auth.getClient()).getAccessToken();

const res = await fetch(`https://playintegrity.googleapis.com/v1/${pkg}:decodeIntegrityToken`, {
  method: 'POST',
  headers: { authorization: `Bearer ${accessToken.token}`, 'content-type': 'application/json' },
  body: JSON.stringify({ integrity_token: token }),
});
const text = await res.text();
console.log('HTTP', res.status, '·', pkg);
try { console.log(JSON.stringify(JSON.parse(text), null, 2)); } catch { console.log(text); }
