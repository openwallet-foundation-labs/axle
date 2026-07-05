import { Inject, Injectable } from '@nestjs/common';
import { eq } from 'drizzle-orm';
import type { JWK } from 'jose';
import { randomUUID } from 'node:crypto';
import { DRIZZLE, type DrizzleDb } from '../db/drizzle.module';
import { walletInstances, type WalletInstanceRow } from '../db/schema';

export interface WalletInstance {
  instanceId: string;
  publicJwk: JWK; // the wallet instance key (bound into the WUA cnf)
  platform: string;
  createdAt: number;
  revoked: boolean;
  revokedAt: number | null;
}

/** Registry of wallet instances, persisted in SQLite via Drizzle. */
@Injectable()
export class InstanceRepository {
  constructor(@Inject(DRIZZLE) private readonly db: DrizzleDb) {}

  async create(publicJwk: JWK, platform: string): Promise<WalletInstance> {
    const row = {
      instanceId: randomUUID(),
      publicJwk: JSON.stringify(publicJwk),
      platform,
      createdAt: Date.now(),
      revoked: false,
      revokedAt: null,
    };
    await this.db.insert(walletInstances).values(row);
    return this.toModel(row as WalletInstanceRow);
  }

  async get(instanceId: string): Promise<WalletInstance | null> {
    const rows = await this.db.select().from(walletInstances).where(eq(walletInstances.instanceId, instanceId));
    return rows[0] ? this.toModel(rows[0]) : null;
  }

  /** Soft-revoke: the instance can no longer obtain a WUA. Idempotent; false if unknown. */
  async revoke(instanceId: string): Promise<boolean> {
    if (!(await this.get(instanceId))) return false;
    await this.db
      .update(walletInstances)
      .set({ revoked: true, revokedAt: Date.now() })
      .where(eq(walletInstances.instanceId, instanceId));
    return true;
  }

  private toModel(row: WalletInstanceRow): WalletInstance {
    return {
      instanceId: row.instanceId,
      publicJwk: JSON.parse(row.publicJwk) as JWK,
      platform: row.platform,
      createdAt: Number(row.createdAt),
      revoked: Boolean(row.revoked),
      revokedAt: row.revokedAt == null ? null : Number(row.revokedAt),
    };
  }
}
