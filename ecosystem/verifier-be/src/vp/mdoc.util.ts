/**
 * Recursively convert Maps / Buffers / Uint8Arrays (as `@lukas.j.han/mdoc` returns decoded CBOR) into
 * JSON-safe plain values, so verified mdoc claims can be returned to the API caller. Ported from the EUDI
 * research module. Map → object; bytes → base64 data URI; objects with `toJSON` (e.g. CBOR DateOnly) → toJSON().
 */
export function toPlainObject(value: unknown): unknown {
  if (value instanceof Map) {
    return Object.fromEntries(Array.from(value.entries(), ([k, v]) => [k, toPlainObject(v)]));
  }
  if (Buffer.isBuffer(value) || value instanceof Uint8Array) {
    return `data:application/octet-stream;base64,${Buffer.from(value).toString('base64')}`;
  }
  if (Array.isArray(value)) {
    return value.map(toPlainObject);
  }
  if (value !== null && typeof value === 'object' && value.constructor === Object) {
    return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, toPlainObject(v)]));
  }
  if (value !== null && typeof value === 'object' && 'toJSON' in value && typeof (value as { toJSON?: unknown }).toJSON === 'function') {
    return (value as { toJSON(): unknown }).toJSON();
  }
  return value;
}
