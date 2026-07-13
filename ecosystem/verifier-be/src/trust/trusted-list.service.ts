import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { X509Certificate, verify as cryptoVerify } from 'node:crypto';
import * as x509 from '@peculiar/x509';

const DEFAULT_BASE = 'https://trusted-list.vercel.app/tl';
const CACHE_TTL_MS = 15 * 60 * 1000;

/** The issuer trust anchors a presented credential must chain to, by credential kind. */
export interface IssuerAnchors {
  /** PID Issuer CA(s) — the PID (SD-JWT VC + mdoc) leaf DSC chains to these. */
  pid: x509.X509Certificate[];
  /** Attestation CA(s) — the mDL (mdoc) leaf DSC chains to these. */
  attestation: x509.X509Certificate[];
}

/**
 * Resolves issuer CA trust anchors from the JAdES-signed Trusted Lists (ETSI TS 119 602) the Scheme Operator
 * publishes — `pid-issuers.jades.json` (PID Issuer CA) and `attestation-issuers.jades.json` (Attestation CA).
 * Fetches each list, verifies the Scheme Operator's JAdES (ES256) signature, extracts the listed service
 * certificates, and caches the result. The verifier checks a presented credential's x5c against these.
 */
@Injectable()
export class TrustedListService {
  private readonly logger = new Logger(TrustedListService.name);
  private readonly base: string;
  private cache?: { anchors: IssuerAnchors; at: number };

  constructor(config: ConfigService) {
    this.base = (config.get<string>('TRUSTED_LIST_BASE_URL') ?? DEFAULT_BASE).replace(/\/$/, '');
  }

  async getIssuerAnchors(): Promise<IssuerAnchors> {
    if (this.cache && Date.now() - this.cache.at < CACHE_TTL_MS) return this.cache.anchors;
    const [pid, attestation] = await Promise.all([
      this.fetchList('pid-issuers'),
      this.fetchList('attestation-issuers'),
    ]);
    const anchors: IssuerAnchors = { pid, attestation };
    this.cache = { anchors, at: Date.now() };
    this.logger.log(`trusted lists loaded: ${pid.length} PID CA(s), ${attestation.length} Attestation CA(s)`);
    return anchors;
  }

  /** All issuer anchors as DER (for @lukas.j.han/mdoc `trustedCertificates`). */
  async getIssuerAnchorsDer(): Promise<Uint8Array[]> {
    const a = await this.getIssuerAnchors();
    return [...a.pid, ...a.attestation].map((c) => new Uint8Array(c.rawData));
  }

  private async fetchList(name: string): Promise<x509.X509Certificate[]> {
    const url = `${this.base}/${name}.jades.json`;
    const res = await fetch(url, { signal: AbortSignal.timeout(8000) });
    if (!res.ok) throw new Error(`trusted list fetch failed (${name}): ${res.status}`);
    const jades = (await res.json()) as { protected: string; payload: string; signature: string };
    this.verifyJades(jades);

    const lote = JSON.parse(Buffer.from(jades.payload, 'base64url').toString()) as {
      trustedEntitiesList: Array<{
        trustedEntityServices: Array<{ serviceDigitalIdentity: { x509Certificate: string } }>;
      }>;
    };
    return lote.trustedEntitiesList.flatMap((e) =>
      e.trustedEntityServices.map((s) => new x509.X509Certificate(s.serviceDigitalIdentity.x509Certificate)),
    );
  }

  /** Verify the Scheme Operator's JAdES (ES256) signature over the list, against the embedded x5c[0]. */
  private verifyJades(jades: { protected: string; payload: string; signature: string }): void {
    const header = JSON.parse(Buffer.from(jades.protected, 'base64url').toString());
    const cert = new X509Certificate(`-----BEGIN CERTIFICATE-----\n${header.x5c[0]}\n-----END CERTIFICATE-----`);
    const ok = cryptoVerify(
      'sha256',
      Buffer.from(`${jades.protected}.${jades.payload}`),
      { key: cert.publicKey, dsaEncoding: 'ieee-p1363' },
      Buffer.from(jades.signature, 'base64url'),
    );
    if (!ok) throw new Error('trusted list JAdES signature invalid');
  }
}
