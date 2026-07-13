import { Injectable } from '@nestjs/common';
import { CoseKey, Issuer, SignatureAlgorithm } from '@lukas.j.han/mdoc';
import type { JWK } from 'jose';
import { KeystoreService, type SignerType } from '../crypto/keystore.service';
import { mdocContext } from './mdoc.context';

export interface MdocNamespace {
  namespace: string;
  claims: Record<string, unknown>;
}

/**
 * ISO mdoc issuance (ISO/IEC 18013-5 IssuerSigned / MSO). Builds the IssuerSigned structure, signs the MSO as
 * COSE_Sign1 (ES256) with the Issuer DSC — the DSC is embedded as the COSE `x5chain` so a verifier resolves
 * the issuing CA from the published Trusted List — binds the holder's device public key, and returns the
 * base64url IssuerSigned for OID4VCI delivery. Used for both PID (mso_mdoc) and mDL.
 */
@Injectable()
export class MdocService {
  constructor(private readonly keystore: KeystoreService) {}

  async issue(
    doctype: string,
    namespaces: MdocNamespace[],
    deviceKey: JWK,
    signerType: SignerType,
    status?: { idx: number; uri: string },
  ): Promise<string> {
    const signer = this.keystore.getSigner(signerType);
    const issuer = new Issuer(doctype, mdocContext);
    for (const { namespace, claims } of namespaces) {
      issuer.addIssuerNamespace(namespace, claims);
    }

    const issuerSigned = await issuer.sign({
      signingKey: CoseKey.fromJwk(signer.privateJwk as Record<string, unknown>),
      certificate: signer.certDer,
      algorithm: SignatureAlgorithm.ES256,
      digestAlgorithm: 'SHA-256',
      deviceKeyInfo: {
        deviceKey: CoseKey.fromJwk(deviceKey as Record<string, unknown>),
      },
      validityInfo: {
        signed: new Date(),
        validFrom: new Date(),
        validUntil: new Date('2035-12-31T23:59:59.999Z'),
      },
      // ISO/IEC 18013-5 MSO `status.status_list = { idx, uri }` — the IETF Token Status List reference (the
      // pointer only; the list token at `uri` is served separately as `statuslist+jwt`). @lukas.j.han/mdoc >= 0.6.0.
      ...(status ? { status: { statusList: { idx: status.idx, uri: status.uri } } } : {}),
    });

    return issuerSigned.encodedForOid4Vci;
  }
}
