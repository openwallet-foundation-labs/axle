import { Injectable, Logger } from '@nestjs/common';
import { createHash, randomBytes } from 'node:crypto';
import { type JWK } from 'jose';
import { cborEncode, cborDecode, DataItem } from '@lukas.j.han/mdoc';
import { Aes128Gcm, CipherSuite, DhkemP256HkdfSha256, HkdfSha256 } from '@hpke/core';
import { REQUESTABLE, type RequestableCredential, type RequestableKey } from './dcql';
import { generateEncKey } from './enc-key';

/**
 * The `org-iso-mdoc` Digital Credentials API protocol (ISO/IEC 18013-7 Annex C) — the ISO-native alternative to
 * OpenID4VP-over-DC-API. The verifier hands the browser a CBOR `DeviceRequest` plus an `EncryptionInfo` blob
 * (a recipient HPKE public key + nonce); the wallet returns an HPKE-sealed `DeviceResponse`. There is no JAR /
 * `vp_token` envelope and no OpenID4VP metadata — the request is the raw mdoc `DeviceRequest`, and the response
 * is bound to the browser `origin` through the DC-API `SessionTranscript`.
 *
 * Response encryption is HPKE base mode (DHKEM P-256 + HKDF-SHA256 + AES-128-GCM, ISO 18013-7 §C.4), keyed by a
 * per-transaction P-256 key (the private half stays in the session; the public half is the `EncryptionInfo`
 * recipient key). This mirrors the EUDI research module's `iso-mdoc` protocol path.
 */
@Injectable()
export class IsoMdocService {
  private readonly logger = new Logger(IsoMdocService.name);

  /** The credential kinds presentable over org-iso-mdoc: mso_mdoc only (SD-JWT VC has no ISO DeviceResponse). */
  static isSupportedKey(key: string): key is RequestableKey {
    const cred = REQUESTABLE[key as RequestableKey];
    return !!cred && cred.format === 'mso_mdoc';
  }

  /**
   * Builds an org-iso-mdoc session: a base64url CBOR `DeviceRequest` (one `DocRequest` per requested mdoc
   * credential) and an `EncryptionInfo` carrying a fresh recipient HPKE key + nonce. Returns the per-transaction
   * private JWK (to decrypt the response) and the `EncryptionInfo` (bound into the SessionTranscript on verify).
   */
  async createSession(keys: RequestableKey[]): Promise<{
    deviceRequest: string;
    encryptionInfo: string;
    nonce: string;
    encPrivateJwk: JWK;
  }> {
    const mdocKeys = keys.filter((k) => IsoMdocService.isSupportedKey(k));
    if (mdocKeys.length === 0) {
      throw new Error('org-iso-mdoc requires at least one mso_mdoc credential (pid_mdoc, mdl)');
    }

    const deviceRequest = this.encodeDeviceRequest(mdocKeys.map((k) => REQUESTABLE[k]));

    // Per-transaction recipient key for HPKE response encryption (ISO 18013-7 §C.4 — DHKEM P-256).
    const { publicJwk, privateJwk } = await generateEncKey();
    const nonce = randomBytes(16);
    const encryptionInfoPayload = ['dcapi', { nonce, recipientPublicKey: this.coseKey(publicJwk) }];
    const encryptionInfo = Buffer.from(cborEncode(encryptionInfoPayload)).toString('base64url');

    this.logger.debug(`org-iso-mdoc session built (docTypes=${mdocKeys.map((k) => REQUESTABLE[k].type).join(',')})`);
    return { deviceRequest, encryptionInfo, nonce: nonce.toString('base64url'), encPrivateJwk: privateJwk };
  }

  /** CBOR `DeviceRequest` (ISO 18013-5 §8.3.2.1.2.1): `{ version, docRequests:[{ itemsRequest }] }`, base64url. */
  private encodeDeviceRequest(creds: RequestableCredential[]): string {
    const deviceRequest = {
      version: '1.0',
      docRequests: creds.map((c) => {
        const nameSpaces = { [c.namespace!]: Object.fromEntries(c.claimNames.map((n) => [n, false])) };
        const itemsRequest = { docType: c.type, nameSpaces };
        // ItemsRequestBytes is a tagged CBOR data item (#6.24) per the DeviceRequest CDDL.
        return { itemsRequest: DataItem.fromData(itemsRequest) };
      }),
    };
    return Buffer.from(cborEncode(deviceRequest)).toString('base64url');
  }

  /** The recipient public key as a COSE_Key map (EC2 / P-256) for the DC-API `EncryptionInfo`. */
  private coseKey(jwk: JWK): Map<number, number | Uint8Array> {
    const b64u = (v?: string) => new Uint8Array(Buffer.from(v ?? '', 'base64url'));
    return new Map<number, number | Uint8Array>([
      [1, 2], // kty: EC2
      [-1, 1], // crv: P-256
      [-2, b64u(jwk.x)], // x
      [-3, b64u(jwk.y)], // y
    ]);
  }

  /**
   * Decrypts the wallet's HPKE-sealed DC-API response to the base64url `DeviceResponse`. The response CBOR is
   * `[ "dcapi", { enc, cipherText } ]`; the HPKE `info` is the same SessionTranscript the DeviceResponse is
   * verified against (origin- + EncryptionInfo-bound), so a response replayed to another origin fails to open.
   */
  async decryptResponse(response: string, origin: string, encryptionInfo: string, encPrivateJwk: JWK): Promise<string> {
    const [, body] = cborDecode(Buffer.from(response, 'base64url')) as [unknown, Map<string, Uint8Array>];
    const enc = body.get('enc');
    const cipherText = body.get('cipherText');
    if (!enc || !cipherText) throw new Error('org-iso-mdoc response missing enc/cipherText');

    const info = buildIsoMdocSessionTranscript(origin, encryptionInfo);
    const toAb = (u8: Uint8Array): ArrayBuffer =>
      u8.buffer.slice(u8.byteOffset, u8.byteOffset + u8.byteLength) as ArrayBuffer;

    const suite = new CipherSuite({ kem: new DhkemP256HkdfSha256(), kdf: new HkdfSha256(), aead: new Aes128Gcm() });
    const recipientKey = await suite.kem.importKey('jwk', encPrivateJwk as JsonWebKey, false);
    const recipient = await suite.createRecipientContext({ recipientKey, enc: toAb(enc), info: toAb(info) });
    const pt = await recipient.open(toAb(cipherText));
    return Buffer.from(new Uint8Array(pt)).toString('base64url');
  }
}

/**
 * The DC-API `SessionTranscript` for org-iso-mdoc (ISO/IEC 18013-7 Annex C):
 *   `[ null, null, [ "dcapi", SHA-256( CBOR([ EncryptionInfo, origin ]) ) ] ]`
 * Used both as the HPKE `info` (response confidentiality) and as the mdoc device-auth transcript (integrity),
 * binding the presentation to this verifier's `EncryptionInfo` and the calling web origin.
 */
export function buildIsoMdocSessionTranscript(origin: string, encryptionInfo: string): Uint8Array {
  const dcapiInfoHash = createHash('sha256').update(cborEncode([encryptionInfo, origin])).digest();
  return cborEncode([null, null, ['dcapi', dcapiInfoHash]]);
}
