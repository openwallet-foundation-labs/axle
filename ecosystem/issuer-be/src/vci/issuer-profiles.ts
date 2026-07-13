/**
 * Issuer policy profiles. Each profile is a distinct OpenID4VCI **Credential Issuer** (its own metadata
 * document at its own `.well-known/openid-credential-issuer/<seg>` path and its own `credential_issuer`
 * identifier), differing only in the two policies a wallet keys off the metadata for:
 *
 *   • `enc`   → `credential_response_encryption.encryption_required` (true ⇒ the wallet MUST encrypt the
 *               Credential Response; the issuer rejects a plaintext one). Fully standard.
 *   • `batch` → `batch_credential_issuance.batch_size` (the MAX credentials per request; a `batch:1` profile
 *               therefore forbids batching, a `batch:3` profile permits up to three). Fully standard.
 *
 * All profiles share the SAME real endpoints (token/nonce/credential/… under the base `/eudi-issuer` prefix)
 * and the SAME authorization server; only the metadata identity + policy flags differ. This replaces the
 * earlier non-standard `demo_options` offer hint — the operator's choice now selects which standard metadata
 * the wallet fetches (via the offer's `credential_issuer`).
 */
export interface IssuerProfile {
  /** URL path suffix on `eudi-issuer` ('' = the default profile). */
  key: string;
  enc: boolean;
  batch: 1 | 3;
}

export const ISSUER_PROFILES: IssuerProfile[] = [
  { key: '', enc: false, batch: 1 },
  { key: 'enc', enc: true, batch: 1 },
  { key: 'batch', enc: false, batch: 3 },
  { key: 'enc-batch', enc: true, batch: 3 },
];

/** Picks the profile matching the operator's (encrypted, batch) choice; falls back to the default. */
export function resolveProfile(enc: boolean, batch: number): IssuerProfile {
  const b = batch === 3 ? 3 : 1;
  return ISSUER_PROFILES.find((p) => p.enc === enc && p.batch === b) ?? ISSUER_PROFILES[0];
}

/** Resolves a profile from a URL suffix key ('' → default, 'enc' → …); undefined if unknown. */
export function profileByKey(key: string): IssuerProfile | undefined {
  return ISSUER_PROFILES.find((p) => p.key === key);
}

/** This profile's Credential Issuer Identifier: the base issuer, with the profile suffix appended. */
export function credentialIssuerId(baseIss: string, p: IssuerProfile): string {
  return p.key ? `${baseIss}-${p.key}` : baseIss;
}

/** Every valid Credential Issuer Identifier (all profiles) — used to accept the proof `aud`. */
export function allCredentialIssuerIds(baseIss: string): string[] {
  return ISSUER_PROFILES.map((p) => credentialIssuerId(baseIss, p));
}
