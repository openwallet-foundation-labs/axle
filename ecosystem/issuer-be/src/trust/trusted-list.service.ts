import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { X509Certificate, verify as cryptoVerify } from 'node:crypto';
import * as x509 from '@peculiar/x509';

const DEFAULT_URL = 'https://trusted-list.vercel.app/tl/wallet-providers.jades.json';
const CACHE_TTL_MS = 15 * 60 * 1000;

/**
 * Resolves the Wallet Provider CA trust anchors from the JAdES-signed Wallet Providers Trusted List (ETSI TS
 * 119 602) — the anchors a Wallet Unit Attestation (WUA) must chain to. Fetches the list, verifies the Scheme
 * Operator's JAdES signature, extracts each listed service certificate, and caches the result.
 */
@Injectable()
export class TrustedListService {
  private readonly logger = new Logger(TrustedListService.name);
  private readonly url: string;
  private readonly base: string;
  private readonly soCertPem?: string;
  private soCert?: X509Certificate;
  private cache?: { cas: x509.X509Certificate[]; at: number };

  constructor(config: ConfigService) {
    this.url = config.get<string>('TRUSTED_LIST_URL') ?? DEFAULT_URL;
    // The list directory (for the published `scheme-operator.pem`): strip the `.jades.json` filename.
    this.base = this.url.replace(/\/[^/]*$/, '');
    // Pinned Scheme Operator signing cert (PEM). If unset, the published `scheme-operator.pem` is fetched and
    // pinned on first use — better than blindly trusting each list's own embedded `x5c[0]`.
    this.soCertPem = config.get<string>('ISSUER_SCHEME_OPERATOR_CERT');
  }

  /** The pinned Scheme Operator signing certificate (env-configured, else the published scheme-operator.pem). */
  private async schemeOperator(): Promise<X509Certificate> {
    if (this.soCert) return this.soCert;
    let pem = this.soCertPem;
    if (!pem) {
      const res = await fetch(`${this.base}/scheme-operator.pem`, { signal: AbortSignal.timeout(8000) });
      if (!res.ok) throw new Error(`scheme-operator cert fetch failed: ${res.status}`);
      pem = await res.text();
    }
    this.soCert = new X509Certificate(pem);
    return this.soCert;
  }

  async getWalletProviderCAs(): Promise<x509.X509Certificate[]> {
    if (this.cache && Date.now() - this.cache.at < CACHE_TTL_MS) return this.cache.cas;

    const so = await this.schemeOperator();
    const res = await fetch(this.url, { signal: AbortSignal.timeout(8000) });
    if (!res.ok) throw new Error(`trusted list fetch failed: ${res.status}`);
    const jades = (await res.json()) as { protected: string; payload: string; signature: string };

    this.verifyJades(jades, so);

    const lote = JSON.parse(Buffer.from(jades.payload, 'base64url').toString()) as {
      trustedEntitiesList: Array<{
        trustedEntityServices: Array<{ serviceDigitalIdentity: { x509Certificate: string } }>;
      }>;
    };
    const cas = lote.trustedEntitiesList.flatMap((e) =>
      e.trustedEntityServices.map((s) => new x509.X509Certificate(s.serviceDigitalIdentity.x509Certificate)),
    );
    this.cache = { cas, at: Date.now() };
    this.logger.log(`trusted list loaded: ${cas.length} Wallet Provider CA(s) from ${this.url}`);
    return cas;
  }

  /**
   * Verify the Scheme Operator's JAdES (ES256) signature over the list, **pinned** to the SO anchor: the
   * embedded `x5c[0]` MUST equal the pinned SO cert, and the signature is verified with the pinned key.
   */
  private verifyJades(jades: { protected: string; payload: string; signature: string }, so: X509Certificate): void {
    const header = JSON.parse(Buffer.from(jades.protected, 'base64url').toString());
    const embedded = new X509Certificate(`-----BEGIN CERTIFICATE-----\n${header.x5c[0]}\n-----END CERTIFICATE-----`);
    if (Buffer.from(embedded.raw).toString('base64') !== Buffer.from(so.raw).toString('base64')) {
      throw new Error('trusted list is not signed by the pinned Scheme Operator');
    }
    const ok = cryptoVerify(
      'sha256',
      Buffer.from(`${jades.protected}.${jades.payload}`),
      { key: so.publicKey, dsaEncoding: 'ieee-p1363' },
      Buffer.from(jades.signature, 'base64url'),
    );
    if (!ok) throw new Error('trusted list JAdES signature invalid');
  }
}
