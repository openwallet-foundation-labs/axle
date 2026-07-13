import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { SignJWT, jwtVerify, importJWK, type JWTPayload } from 'jose';
import { KeystoreService } from '../crypto/keystore.service';

/**
 * Signs and verifies the Issuer's own ES256 JWTs — access tokens, c_nonces, and the Token Status List token —
 * using the PID Document Signer key. Internal artifacts (access tokens, c_nonces) are verified only by this
 * Issuer, so they carry `kid`; the Status List token is consumed by third parties, so it carries `x5c`.
 */
@Injectable()
export class IssuerJwtService {
  constructor(
    private readonly keystore: KeystoreService,
    private readonly config: ConfigService,
  ) {}

  get issuer(): string {
    return this.config.getOrThrow<string>('ISSUER_BASE_URL');
  }

  private privateKey() {
    return importJWK(this.keystore.getSigner('pid').privateJwk, 'ES256');
  }

  private publicKey() {
    return importJWK(this.keystore.getSigner('pid').publicJwk, 'ES256');
  }

  async sign(
    payload: JWTPayload,
    opts: { typ?: string; expSec?: number; aud?: string; sub?: string; x5c?: boolean; iss?: string } = {},
  ): Promise<string> {
    const signer = this.keystore.getSigner('pid');
    const now = Math.floor(Date.now() / 1000);
    let jwt = new SignJWT(payload)
      .setProtectedHeader({
        alg: 'ES256',
        ...(opts.typ ? { typ: opts.typ } : {}),
        ...(opts.x5c ? { x5c: signer.x5c } : { kid: signer.kid }),
      })
      .setIssuedAt(now)
      .setIssuer(opts.iss ?? this.issuer);
    if (opts.expSec) jwt = jwt.setExpirationTime(now + opts.expSec);
    if (opts.aud) jwt = jwt.setAudience(opts.aud);
    if (opts.sub) jwt = jwt.setSubject(opts.sub);
    return jwt.sign(await this.privateKey());
  }

  async verify(jwt: string, opts: { typ?: string; aud?: string } = {}): Promise<JWTPayload> {
    const { payload } = await jwtVerify(jwt, await this.publicKey(), {
      issuer: this.issuer,
      audience: opts.aud,
      ...(opts.typ ? { typ: opts.typ } : {}),
    });
    return payload;
  }
}
