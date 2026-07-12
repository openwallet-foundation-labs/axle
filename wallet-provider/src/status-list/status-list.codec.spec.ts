import { inflateSync } from 'node:zlib';
import { encodeStatusList, STATUS_INVALID, STATUS_VALID } from './status-list.codec';

/** Decode a `{bits, lst}` status list and read the status at an index (mirror of the SDK client / §4). */
function statusAt(lst: string, bits: number, idx: number): number {
  const bytes = inflateSync(Buffer.from(lst.replace(/-/g, '+').replace(/_/g, '/'), 'base64'));
  const entriesPerByte = 8 / bits;
  const shift = (idx % entriesPerByte) * bits;
  return (bytes[Math.floor(idx / entriesPerByte)] >> shift) & ((1 << bits) - 1);
}

describe('encodeStatusList', () => {
  it('matches the IETF Token Status List §4.2 bits=1 test vector', () => {
    const statuses = [1, 0, 0, 1, 1, 1, 0, 1, 1, 1, 0, 0, 0, 1, 0, 1];
    const entries = statuses.map((status, idx) => ({ idx, status }));
    expect(encodeStatusList(entries, 1)).toEqual({ bits: 1, lst: 'eNrbuRgAAhcBXQ' });
  });

  it('matches the IETF Token Status List §4.2 bits=2 test vector', () => {
    const statuses = [1, 2, 0, 3, 0, 1, 0, 1, 1, 2, 3, 3];
    const entries = statuses.map((status, idx) => ({ idx, status }));
    expect(encodeStatusList(entries, 2)).toEqual({ bits: 2, lst: 'eNo76fITAAPfAgc' });
  });

  it('flips only the revoked instance bit (round-trip)', () => {
    // instances at idx 0,1,2 — only idx 1 revoked
    const entries = [
      { idx: 0, status: STATUS_VALID },
      { idx: 1, status: STATUS_INVALID },
      { idx: 2, status: STATUS_VALID },
    ];
    const { bits, lst } = encodeStatusList(entries, 1);
    expect(statusAt(lst, bits, 0)).toBe(STATUS_VALID);
    expect(statusAt(lst, bits, 1)).toBe(STATUS_INVALID);
    expect(statusAt(lst, bits, 2)).toBe(STATUS_VALID);
  });

  it('encodes an empty list as a single VALID byte', () => {
    const { lst } = encodeStatusList([], 1);
    expect(statusAt(lst, 1, 0)).toBe(STATUS_VALID);
  });
});
