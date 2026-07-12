import { pgTable, uuid, varchar, timestamp, boolean, jsonb, integer } from 'drizzle-orm/pg-core';
import { randomUUID } from 'node:crypto';
import type { JWK } from 'jose';

/** Registered wallet instances. `public_jwk` is the instance key; revocation is a soft flag. */
export const walletInstances = pgTable('wallet_instances', {
  instanceId: uuid('instance_id')
    .primaryKey()
    .$defaultFn(() => randomUUID()),
  publicJwk: jsonb('public_jwk').$type<JWK>().notNull(),
  platform: varchar('platform', { length: 20 }).notNull(),
  createdAt: timestamp('created_at').defaultNow().notNull(),
  revoked: boolean('revoked').notNull().default(false),
  revokedAt: timestamp('revoked_at'),
  // Token Status List index for this instance's WUA (bit flipped to 1 on revoke).
  statusIdx: integer('status_idx').generatedByDefaultAsIdentity().notNull(),
});

export type WalletInstanceRow = typeof walletInstances.$inferSelect;
