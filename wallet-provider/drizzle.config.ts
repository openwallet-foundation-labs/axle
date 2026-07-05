import type { Config } from 'drizzle-kit';

// Production migration path: `npx drizzle-kit generate` then apply.
// Dev boot uses CREATE TABLE IF NOT EXISTS (db/drizzle.module.ts).
export default {
  schema: './src/db/schema.ts',
  out: './drizzle',
  dialect: 'sqlite',
  dbCredentials: { url: process.env.DB_PATH ?? 'wallet-provider.db' },
} satisfies Config;
