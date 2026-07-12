// JAdES Baseline-B signature (ETSI TS 119 182-1) over the LoTE, using @lukas.j.han/jades (fork with the
// x5c/x5t#S256 + empty-header fixes). JSON serialization so a signature timestamp (B-T) can later be added
// under the unprotected `etsiU` header. Header shape mirrors the Hopae QTSP pipeline (qtsp-script): the
// signing cert is bound both by reference (x5t#S256) and by value (x5c), with sigT critical.
import { createPrivateKey } from 'node:crypto';
import { Token, ProtectedHeaders, parseCerts, generateX5c, generateX5tS256, generateKid } from '@lukas.j.han/jades';

export function signJades(lote, soKeystore, at = new Date()) {
  const certs = parseCerts(soKeystore.certPem);
  const headers = new ProtectedHeaders({
    alg: 'ES256',
    cty: 'json',
    kid: generateKid(certs[0]),
    x5c: generateX5c(certs),
    x5tS256: generateX5tS256(certs),
    sigT: at.toISOString().replace(/\.\d{3}Z$/, 'Z'), // JAdES claimed signing time (§5.1.10)
    crit: ['sigT'], // sigT is critical (JAdES §5.1.13)
  });

  const token = new Token(lote);
  token.setProtectedHeaders(headers);
  token.sign('ES256', createPrivateKey(soKeystore.privateKeyPem)); // (alg, key)
  return token.toObject(); // JAdES JSON serialization
}
