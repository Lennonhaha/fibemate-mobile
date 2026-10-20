/**
 * One-time pre-key pool (#68).
 *
 * The registration client used to upload the SM2 *identity* public key as its
 * only "one-time" pre-key. That value is neither one-time nor a pre-key: the
 * server keeps a Set, so re-uploading it adds nothing, and every sender that
 * fetches gets the same key. The pool therefore never drained and one key
 * covered all sessions.
 *
 * This module holds the pure part of the fix: given the current pool and a
 * target size, decide what to add. Generation and persistence are injected so
 * the rule can be tested without loading expo modules.
 */

export type OpkEntry = {
  publicKey: string;
  privateKey: string;
};

export function isOpkEntry(value: unknown): value is OpkEntry {
  if (!value || typeof value !== 'object') return false;
  const e = value as Record<string, unknown>;
  return (
    typeof e.publicKey === 'string' &&
    typeof e.privateKey === 'string' &&
    e.publicKey.length > 0 &&
    e.privateKey.length > 0
  );
}

/** Parse a stored pool, dropping anything that is not a well-formed entry. */
export function parsePool(raw: string | null): OpkEntry[] {
  if (!raw) return [];
  try {
    const parsed: unknown = JSON.parse(raw);
    if (!Array.isArray(parsed)) return [];
    return parsed.filter(isOpkEntry);
  } catch {
    return [];
  }
}

/**
 * Grow the pool to `target` entries.
 *
 * A generator that keeps returning the same key would otherwise loop forever,
 * so the attempt count is bounded. Returning a short pool is deliberate: the
 * caller can still upload what it has, and the next call retries.
 */
export function refillPool(
  pool: OpkEntry[],
  target: number,
  generate: () => OpkEntry
): OpkEntry[] {
  const out = pool.filter(isOpkEntry).slice();
  const seen = new Set(out.map((e) => e.publicKey));
  const limit = Math.max(0, target - out.length) * 4 + 1;
  for (let tries = 0; out.length < target && tries < limit; tries++) {
    const next = generate();
    if (!isOpkEntry(next) || seen.has(next.publicKey)) continue;
    seen.add(next.publicKey);
    out.push(next);
  }
  return out;
}

/** Public halves only: private pre-keys never leave the device. */
export function publicKeys(pool: OpkEntry[]): string[] {
  return pool.map((e) => e.publicKey);
}
