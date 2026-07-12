import { Injectable } from '@nestjs/common';
import * as jose from 'jose';
import { KeystoreService } from '../attestation/keystore.service';
import { InstanceRepository } from '../wallet-provider/instance.repository';
import { encodeStatusList, statusListUri, STATUS_INVALID, STATUS_VALID, STATUS_LIST_ID } from './status-list.codec';
import { StatusListRevision } from './status-list-revision';

/** Seconds a consumer may cache the status list token before refetching (§5.1 `ttl`). */
const STATUS_LIST_TTL = 300;
/** How long this replica reuses a built token before rebuilding (bounds cross-replica revoke staleness). */
const CACHE_TTL_MS = 60_000;
/** Pad the list to a multiple of this many entries, so newly-registered instances have headroom. */
const CAPACITY_CHUNK = 2048;

/**
 * Publishes wallet-instance revocation via an IETF Token Status List (draft-ietf-oauth-status-list): each
 * instance owns a bit index; its WUA carries a `status.status_list = {idx, uri}` reference, and this service
 * serves the signed Status List Token (typ `statuslist+jwt`) whose bit flips to INVALID on revoke. Issuers /
 * relying parties then check revocation by fetching one compact list instead of calling `/status` per instance.
 *
 * The token is cached and only rebuilt when a revocation bumps the revision or the cache TTL lapses — not on
 * every request. Registrations don't invalidate the cache: their (VALID) bit falls in the padded headroom.
 */
@Injectable()
export class StatusListService {
  private cache: { token: string; builtAt: number; revision: number } | null = null;

  constructor(
    private readonly keystore: KeystoreService,
    private readonly instances: InstanceRepository,
    private readonly revision: StatusListRevision,
  ) {}

  /** The status list URI — a WUA's `status_list.uri` and the token's `sub` MUST both equal this. */
  uri(id: string = STATUS_LIST_ID): string {
    return statusListUri(this.keystore.issuer, id);
  }

  /** Returns the Status List Token (§5.1), rebuilding only on revocation change or cache expiry. */
  async issueToken(id: string = STATUS_LIST_ID): Promise<string> {
    const rev = this.revision.current;
    if (this.cache && this.cache.revision === rev && Date.now() - this.cache.builtAt < CACHE_TTL_MS) {
      return this.cache.token;
    }
    const token = await this.build(id);
    this.cache = { token, builtAt: Date.now(), revision: rev };
    return token;
  }

  private async build(id: string): Promise<string> {
    const entries = await this.instances.allStatusEntries();
    const maxIdx = entries.reduce((m, e) => Math.max(m, e.statusIdx), -1);
    const capacity = (Math.floor((maxIdx + 1) / CAPACITY_CHUNK) + 1) * CAPACITY_CHUNK; // headroom for new instances
    const statusList = encodeStatusList(
      entries.map((e) => ({ idx: e.statusIdx, status: e.revoked ? STATUS_INVALID : STATUS_VALID })),
      1,
      capacity,
    );
    return new jose.SignJWT({ status_list: statusList, ttl: STATUS_LIST_TTL })
      .setProtectedHeader({ typ: 'statuslist+jwt', alg: 'ES256', x5c: this.keystore.x5c })
      .setSubject(this.uri(id))
      .setIssuer(this.keystore.issuer)
      .setIssuedAt()
      .setExpirationTime('1h')
      .sign(this.keystore.signingKey);
  }
}
