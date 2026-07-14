import { Controller, Get, Headers, Param, Res } from '@nestjs/common';
import type { FastifyReply } from 'fastify';
import { MetadataService } from './metadata.service';
import { profileByKey } from './issuer-profiles';

/** True when the Accept header offers `application/jwt` (a wallet that supports signed metadata, §12.2.2). */
function acceptsSignedJwt(accept?: string): boolean {
  return !!accept && accept.toLowerCase().includes('application/jwt');
}

/**
 * OpenID4VCI / OAuth metadata. These routes are excluded from the /eudi-issuer global prefix (see main.ts):
 * RFC 8414 places the well-known segment at the origin root with the issuer path segment appended.
 */
@Controller()
export class WellKnownController {
  constructor(private readonly metadata: MetadataService) {}

  /**
   * Credential Issuer Metadata, one document per policy profile. `eudi-issuer` is the default; `eudi-issuer-enc`,
   * `eudi-issuer-batch`, `eudi-issuer-enc-batch` carry the encryption-required / batch=3 policies. ETSI TS 119
   * 472-3 ISS-MDATA-4.2.1-01: served as signed metadata (JWS with the access cert in x5c).
   */
  @Get('.well-known/openid-credential-issuer/:issuerSeg')
  async credentialIssuer(
    @Param('issuerSeg') issuerSeg: string,
    @Headers('accept') accept: string | undefined,
    @Res() reply: FastifyReply,
  ): Promise<void> {
    const key = issuerSeg === 'eudi-issuer' ? '' : issuerSeg.startsWith('eudi-issuer-') ? issuerSeg.slice('eudi-issuer-'.length) : null;
    const profile = key === null ? undefined : profileByKey(key);
    if (!profile) {
      await reply.status(404).send({ statusCode: 404, error: 'Not Found', message: 'unknown credential issuer' });
      return;
    }
    // §12.2.2: honour the wallet's Accept — signed application/jwt when it asks, unsigned application/json otherwise.
    if (acceptsSignedJwt(accept)) {
      await reply.type('application/jwt').send(await this.metadata.credentialIssuerMetadataJwt(profile));
    } else {
      await reply.type('application/json').send(this.metadata.credentialIssuerMetadataJson(profile));
    }
  }

  @Get('.well-known/oauth-authorization-server/eudi-issuer')
  authorizationServer() {
    return this.metadata.authorizationServerMetadata();
  }
}
