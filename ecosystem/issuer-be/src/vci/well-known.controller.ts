import { Controller, Get, NotFoundException, Param } from '@nestjs/common';
import { MetadataService } from './metadata.service';
import { profileByKey } from './issuer-profiles';

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
  credentialIssuer(@Param('issuerSeg') issuerSeg: string) {
    const key = issuerSeg === 'eudi-issuer' ? '' : issuerSeg.startsWith('eudi-issuer-') ? issuerSeg.slice('eudi-issuer-'.length) : null;
    const profile = key === null ? undefined : profileByKey(key);
    if (!profile) throw new NotFoundException('unknown credential issuer');
    return this.metadata.signedCredentialIssuerMetadata(profile);
  }

  @Get('.well-known/oauth-authorization-server/eudi-issuer')
  authorizationServer() {
    return this.metadata.authorizationServerMetadata();
  }
}
