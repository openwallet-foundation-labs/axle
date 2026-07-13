import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { calculateJwkThumbprint, decodeProtectedHeader, importJWK, jwtVerify, type JWK } from 'jose';
import { TrustedListService } from '../trust/trusted-list.service';
import { OAuthError } from '../vci/oauth-error';
import { verifyX5cToAnchors } from './x5c-chain.util';

/**
 * Verifies the Key Attestation carried in the credential-request proof's JOSE header (`key_attestation`,
 * HAIP §4.5.1 / OID4VCI Appendix D). Confirms the attestation chains to a trusted Wallet Provider CA, is
 * fresh, lists the holder's key in `attested_keys` (PoP↔attestation binding), and — when a nonce is expected
 * — echoes it. When `required` is false (a low-assurance credential config, e.g. a demo mDL) a proof carrying
 * NO attestation is accepted; an attestation that IS present is always validated fully. Globally bypassed by
 * `DEV_ATTESTATION_BYPASS=true`.
 */
@Injectable()
export class KeyAttestationService {
  private readonly logger = new Logger(KeyAttestationService.name);

  constructor(
    private readonly trust: TrustedListService,
    private readonly config: ConfigService,
  ) {}

  async verify(proofHeader: Record<string, unknown>, holderJwk: JWK, expectedNonce?: string, required = true): Promise<void> {
    if (this.config.get<string>('DEV_ATTESTATION_BYPASS') === 'true') return;

    const keyAtt = proofHeader['key_attestation'] as string | undefined;
    if (!keyAtt) {
      if (!required) return; // this credential config accepts a bare jwt proof (PoP only, no WSCD binding)
      throw new OAuthError('invalid_proof', 'key attestation required');
    }

    try {
      const kah = decodeProtectedHeader(keyAtt);
      if (kah.typ !== 'key-attestation+jwt') throw new Error('bad key-attestation typ');
      if (!kah.x5c?.length) throw new Error('key attestation missing x5c');
      const leafJwk = await verifyX5cToAnchors(kah.x5c, await this.trust.getWalletProviderCAs());
      const { payload } = await jwtVerify(keyAtt, await importJWK(leafJwk, kah.alg ?? 'ES256'));

      const now = Math.floor(Date.now() / 1000);
      if (typeof payload.iat !== 'number' || payload.iat > now + 60 || payload.iat < now - 300) {
        throw new Error('key attestation iat out of window');
      }
      if (typeof payload.exp === 'number' && payload.exp < now) throw new Error('key attestation expired');
      if (expectedNonce && payload.nonce !== expectedNonce) throw new Error('key attestation nonce mismatch');

      const attested = payload.attested_keys as JWK[] | undefined;
      if (!attested?.length) throw new Error('no attested_keys');
      const holderTp = await calculateJwkThumbprint(holderJwk, 'sha256');
      const tps = await Promise.all(attested.map((k) => calculateJwkThumbprint(k, 'sha256')));
      if (!tps.includes(holderTp)) throw new Error('holder key not in attested_keys');
    } catch (e) {
      this.logger.warn(`key attestation rejected: ${(e as Error).message}`);
      throw new OAuthError('invalid_proof', 'key attestation verification failed');
    }
  }
}
