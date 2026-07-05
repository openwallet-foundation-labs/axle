import { integer, sqliteTable, text } from 'drizzle-orm/sqlite-core';

/** Registered wallet instances. `public_jwk` is the instance key JSON; revocation is a soft flag. */
export const walletInstances = sqliteTable('wallet_instances', {
  instanceId: text('instance_id').primaryKey(),
  publicJwk: text('public_jwk').notNull(), // JSON-encoded JWK
  platform: text('platform').notNull(),
  createdAt: integer('created_at').notNull(), // epoch ms
  revoked: integer('revoked', { mode: 'boolean' }).notNull().default(false),
  revokedAt: integer('revoked_at'), // epoch ms | null
});

export type WalletInstanceRow = typeof walletInstances.$inferSelect;
