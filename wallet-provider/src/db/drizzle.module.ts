import { Global, Module } from '@nestjs/common';
import Database from 'better-sqlite3';
import { drizzle, type BetterSQLite3Database } from 'drizzle-orm/better-sqlite3';
import * as schema from './schema';

export const DRIZZLE = Symbol('DRIZZLE');
export type DrizzleDb = BetterSQLite3Database<typeof schema>;

/**
 * SQLite (better-sqlite3) via Drizzle. Dev: the schema is materialized on boot with a
 * `CREATE TABLE IF NOT EXISTS`. Production: swap the driver for Postgres and run drizzle-kit
 * migrations (`drizzle.config.ts`).
 */
@Global()
@Module({
  providers: [
    {
      provide: DRIZZLE,
      useFactory: (): DrizzleDb => {
        const sqlite = new Database(process.env.DB_PATH ?? 'wallet-provider.db');
        sqlite.pragma('journal_mode = WAL');
        sqlite.exec(`CREATE TABLE IF NOT EXISTS wallet_instances (
          instance_id TEXT PRIMARY KEY,
          public_jwk  TEXT NOT NULL,
          platform    TEXT NOT NULL,
          created_at  INTEGER NOT NULL,
          revoked     INTEGER NOT NULL DEFAULT 0,
          revoked_at  INTEGER
        )`);
        return drizzle(sqlite, { schema });
      },
    },
  ],
  exports: [DRIZZLE],
})
export class DrizzleModule {}
