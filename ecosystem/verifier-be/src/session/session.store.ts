import { Injectable, Logger, OnModuleDestroy } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import Redis from 'ioredis';
import type { RpProfile } from '../crypto/keystore.service';

/**
 * A presentation session: the state a verifier holds between issuing a request and verifying the wallet's
 * response. Keyed by an opaque transaction id.
 */
export interface PresentationSession {
  id: string;
  /** The `nonce` bound into the request (and checked against the vp_token / key-binding). */
  nonce: string;
  /** The credential kinds requested (for result shaping). */
  requested: string[];
  /** Delivery channel: `qr` (request_uri + direct_post) or `dc_api` (Digital Credentials API). */
  mode: 'qr' | 'dc_api';
  /** Which RP profile signed the request (its client_id binds the response / mdoc SessionTranscript). */
  rp: RpProfile;
  /** The signed request object (compact JWS) served at `/request/:id` or embedded for the DC API. */
  requestJwt: string;
  /** Web origins the DC API response may come from (dc_api mode only). */
  expectedOrigins?: string[];
  createdAt: number;
  /** Populated once the wallet responds and the vp_token is verified (or verification fails). */
  result?: PresentationResult;
}

export interface PresentationResult {
  status: 'verified' | 'failed';
  /** Per-credential verified claims, keyed by DCQL query id. */
  credentials?: Array<{ queryId: string; format: string; type: string; claims: Record<string, unknown> }>;
  error?: string;
  verifiedAt: number;
}

/**
 * Short-lived presentation state. Redis-backed when `REDIS_URL` is set (shared across replicas, production);
 * otherwise an in-memory Map with lazy TTL expiry (single-replica dev). Keys are namespaced `trp:pres:` so
 * the verifier can share a Redis instance/DB with other services without collisions.
 */
@Injectable()
export class SessionStore implements OnModuleDestroy {
  private readonly logger = new Logger(SessionStore.name);
  private readonly redis?: Redis;
  private readonly mem = new Map<string, { session: PresentationSession; exp: number }>();
  private readonly ttlSec = 10 * 60; // presentation requests are short-lived
  private readonly prefix = 'trp:pres:';

  constructor(config: ConfigService) {
    const url = config.get<string>('REDIS_URL');
    if (url) {
      // `rediss://` selects TLS automatically (ElastiCache in-transit encryption).
      this.redis = new Redis(url, { maxRetriesPerRequest: 3, lazyConnect: false, keyPrefix: this.prefix });
      this.redis.on('error', (e) => this.logger.error(`redis: ${e.message}`));
      this.logger.log('session state: Redis');
    } else {
      this.logger.warn('REDIS_URL unset — using in-memory session state (single-replica only)');
    }
  }

  async put(session: PresentationSession): Promise<void> {
    if (this.redis) {
      await this.redis.set(session.id, JSON.stringify(session), 'EX', this.ttlSec);
    } else {
      this.mem.set(session.id, { session, exp: Date.now() + this.ttlSec * 1000 });
    }
  }

  async get(id: string): Promise<PresentationSession | undefined> {
    if (this.redis) {
      const v = await this.redis.get(id);
      return v ? (JSON.parse(v) as PresentationSession) : undefined;
    }
    const e = this.mem.get(id);
    if (!e) return undefined;
    if (e.exp < Date.now()) {
      this.mem.delete(id);
      return undefined;
    }
    return e.session;
  }

  async onModuleDestroy() {
    await this.redis?.quit();
  }
}
