// DER builders for the X.509 extensions @peculiar/x509 doesn't provide out of the box, used to make the
// issuer CAs (ISO/IEC 18013-5 Annex B IACA profile) and Document Signers (Annex B DS profile + ETSI TS
// 119 412-6 qualified markers) standards-conformant. Same hand-encoding approach as wallet-provider's
// gen-keystore.mjs. Each function returns an @peculiar/x509 Extension.
import * as x509 from '@peculiar/x509';
import { randomBytes } from 'node:crypto';

const derLen = (len) =>
  len < 0x80
    ? [len]
    : (() => {
        const o = [];
        for (let n = len; n > 0; n = Math.floor(n / 256)) o.unshift(n & 0xff);
        return [0x80 | o.length, ...o];
      })();
const derTlv = (tag, body) => [tag, ...derLen(body.length), ...body];
const derOid = (dotted) => {
  const p = dotted.split('.').map(Number);
  const body = [40 * p[0] + p[1]];
  for (let i = 2; i < p.length; i++) {
    const stack = [p[i] & 0x7f];
    for (let v = Math.floor(p[i] / 128); v > 0; v = Math.floor(v / 128)) stack.unshift((v & 0x7f) | 0x80);
    body.push(...stack);
  }
  return derTlv(0x06, body);
};
const derSeq = (...items) => derTlv(0x30, items.flat());
const uriGN = (uri) => derTlv(0x86, [...Buffer.from(uri, 'ascii')]); // GeneralName uniformResourceIdentifier [6]
const ext = (oid, critical, body) => new x509.Extension(oid, critical, Uint8Array.from(body));

// --- OIDs -------------------------------------------------------------------------------------------------
export const OID = {
  qcStatements: '1.3.6.1.5.5.7.1.3',
  aia: '1.3.6.1.5.5.7.1.1',
  caIssuers: '1.3.6.1.5.5.7.48.2',
  issuerAltName: '2.5.29.18',
  crlDistributionPoints: '2.5.29.31',
  etsiQcType: '0.4.0.1862.1.6', // id-etsi-qcs-QcType (EN 319 412-5)
  qctPid: '0.4.0.194126.1.1', // id-etsi-qct-pid  (ETSI TS 119 412-6 §4)
  qctWal: '0.4.0.194126.1.2', // id-etsi-qct-wal  (§5.2)
  qctEaa: '0.4.0.194126.1.3', // id-etsi-qct-eaa  (§6) — attestation/(Q)EAA provider
  mdlDS: '1.0.18013.5.1.2', // id-mdl-kp-mdlDS (ISO/IEC 18013-5 Annex B) — EKU for the mDL Document Signer
};

/** A non-sequential positive serial number from a CSPRNG (ISO 18013-5 Annex B: ≥63 bits, ≤20 octets). */
export function csprngSerial() {
  const b = randomBytes(16);
  b[0] &= 0x7f;
  b[0] |= 0x01; // positive, non-zero leading octet
  return b.toString('hex');
}

/** id-pe-qcStatements carrying one or more ETSI QcType OIDs (non-critical). */
export function qcStatementsExtension(...typeOids) {
  const qcType = derSeq(derOid(OID.etsiQcType), derSeq(...typeOids.map(derOid)));
  return ext(OID.qcStatements, false, derSeq(qcType));
}

/** id-ce-issuerAltName with a single URI (ISO 18013-5 Annex B IACA: contact info, non-critical). */
export function issuerAltNameUri(uri) {
  return ext(OID.issuerAltName, false, derSeq(uriGN(uri)));
}

/** id-ce-cRLDistributionPoints with a single fullName URI distribution point (non-critical). */
export function crlDistributionPointUri(uri) {
  const dpName = derTlv(0xa0, derTlv(0xa0, uriGN(uri))); // [0] distributionPoint → [0] fullName → [6] URI
  return ext(OID.crlDistributionPoints, false, derSeq(derSeq(dpName)));
}

/** id-pe-authorityInfoAccess with a caIssuers URI (points at the issuing CA cert; non-critical). */
export function authorityInfoAccessCaIssuers(uri) {
  return ext(OID.aia, false, derSeq(derSeq(derOid(OID.caIssuers), uriGN(uri))));
}
