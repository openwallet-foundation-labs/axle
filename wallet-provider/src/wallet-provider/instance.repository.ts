import { Inject, Injectable } from '@nestjs/common';
import { eq } from 'drizzle-orm';
import type { JWK } from 'jose';
import { DRIZZLE, type DrizzleDb } from '../db/drizzle.module';
import { walletInstances, type WalletInstanceRow } from '../db/schema';

export interface WalletInstance {
  instanceId: string;
  publicJwk: JWK; // the wallet instance key (bound into the WUA cnf)
  platform: string;
  createdAt: number; // epoch ms
  revoked: boolean;
  revokedAt: number | null; // epoch ms | null
  statusIdx: number; // Token Status List bit index for this instance's WUA
}

/** Registry of wallet instances, persisted in Postgres via Drizzle. */
@Injectable()
export class InstanceRepository {
  constructor(@Inject(DRIZZLE) private readonly db: DrizzleDb) {}

  async create(publicJwk: JWK, platform: string): Promise<WalletInstance> {
    const [row] = await this.db.insert(walletInstances).values({ publicJwk, platform }).returning();
    return this.toModel(row);
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
      .set({ revoked: true, revokedAt: new Date() })
      .where(eq(walletInstances.instanceId, instanceId));
    return true;
  }

  /** All instances' Token Status List bit index + revocation flag, for building the status list. */
  async allStatusEntries(): Promise<{ statusIdx: number; revoked: boolean }[]> {
    return this.db
      .select({ statusIdx: walletInstances.statusIdx, revoked: walletInstances.revoked })
      .from(walletInstances);
  }

  private toModel(row: WalletInstanceRow): WalletInstance {
    return {
      instanceId: row.instanceId,
      publicJwk: row.publicJwk,
      platform: row.platform,
      createdAt: row.createdAt.getTime(),
      revoked: row.revoked,
      revokedAt: row.revokedAt ? row.revokedAt.getTime() : null,
      statusIdx: row.statusIdx,
    };
  }
}
