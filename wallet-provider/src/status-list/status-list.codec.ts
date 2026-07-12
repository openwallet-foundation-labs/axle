import { deflateSync } from 'node:zlib';

/** The single status list this WP publishes for wallet-instance WUAs. */
export const STATUS_LIST_ID = '1';

/** Status Type values (IETF Token Status List §7.1). */
export const STATUS_VALID = 0x00;
export const STATUS_INVALID = 0x01; // revoked / annulled

export type StatusBits = 1 | 2 | 4 | 8;

/** IETF Token Status List §4.2 `StatusList` object. */
export interface StatusList {
  bits: number;
  lst: string;
}

/**
 * Encodes per-token statuses into a Token Status List (draft-ietf-oauth-status-list §4): a packed bit
 * array where each token's `idx` selects a contiguous `bits`-wide slot, packed least-significant-bit first
 * within each byte, then DEFLATE/zlib-compressed and base64url-encoded. Verified against the §4.2 vectors.
 */
export function encodeStatusList(
  entries: ReadonlyArray<{ idx: number; status: number }>,
  bits: StatusBits = 1,
  minEntries = 0,
): StatusList {
  const entriesPerByte = 8 / bits;
  const mask = (1 << bits) - 1;
  const maxIdx = entries.reduce((m, e) => Math.max(m, e.idx), -1);
  // Cover at least `minEntries` so freshly-registered (default VALID) indices aren't out-of-bounds.
  const totalEntries = Math.max(maxIdx + 1, minEntries);
  const byteLength = Math.max(Math.ceil(totalEntries / entriesPerByte), 1);
  const bytes = new Uint8Array(byteLength);
  for (const { idx, status } of entries) {
    const byteIndex = Math.floor(idx / entriesPerByte);
    const shift = (idx % entriesPerByte) * bits;
    bytes[byteIndex] |= (status & mask) << shift;
  }
  return { bits, lst: base64url(deflateSync(bytes, { level: 9 })) };
}

/**
 * The status list URI. The Referenced Token's `status.status_list.uri` and the Status List Token's `sub`
 * MUST both equal this (§5.1, §8.3). Built from the WP issuer so it resolves to `GET {issuer}/status-lists/{id}`.
 */
export function statusListUri(issuer: string, id: string = STATUS_LIST_ID): string {
  return `${issuer}/status-lists/${id}`;
}

function base64url(buf: Buffer): string {
  return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
