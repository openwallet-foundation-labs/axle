import { Injectable, Logger, OnModuleDestroy, OnModuleInit } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { randomBytes } from 'node:crypto';
import Redis from 'ioredis';

const TTL_SECONDS = 5 * 60;

/**
 * Single-use, short-lived challenge nonces (freshness for registration / attestation PoP). Backed by Redis
 * when `REDIS_URL` is set — required for correctness across replicas, since a nonce issued by one pod must
 * be consumable (exactly once) by any pod. Single-use is atomic via `GETDEL`; TTL handles expiry. Without
 * `REDIS_URL` it falls back to an in-memory map (single-replica / local dev only).
 */
@Injectable()
export class NonceService implements OnModuleInit, OnModuleDestroy {
  private readonly logger = new Logger(NonceService.name);
  private redis?: Redis;
  private readonly memory = new Map<string, number>(); // fallback: nonce -> expiry epoch ms

  constructor(private readonly config: ConfigService) {}

  onModuleInit(): void {
    const url = this.config.get<string>('REDIS_URL');
    if (url) {
      this.redis = new Redis(url, { maxRetriesPerRequest: 3 });
      this.redis.on('error', (e) => this.logger.warn(`redis error: ${e.message}`));
      this.logger.log('nonce store: redis');
    } else {
      this.logger.warn('nonce store: in-memory — single-replica only; set REDIS_URL for multi-replica');
    }
  }

  async onModuleDestroy(): Promise<void> {
    await this.redis?.quit();
  }

  async issue(): Promise<string> {
    const nonce = randomBytes(16).toString('base64url');
    if (this.redis) {
      await this.redis.set(key(nonce), '1', 'EX', TTL_SECONDS);
    } else {
      this.sweep();
      this.memory.set(nonce, Date.now() + TTL_SECONDS * 1000);
    }
    return nonce;
  }

  /** Atomically validates and consumes a nonce; returns false if unknown or expired. */
  async consume(nonce: string | undefined): Promise<boolean> {
    if (!nonce) return false;
    if (this.redis) {
      return (await this.redis.getdel(key(nonce))) !== null;
    }
    const expiry = this.memory.get(nonce);
    this.memory.delete(nonce);
    return expiry !== undefined && expiry > Date.now();
  }

  private sweep(): void {
    const now = Date.now();
    for (const [nonce, expiry] of this.memory) if (expiry <= now) this.memory.delete(nonce);
  }
}

function key(nonce: string): string {
  return `wp:nonce:${nonce}`;
}
