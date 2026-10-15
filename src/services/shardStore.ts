/**
 * FIBEMATE Mobile — shard-based secure key storage (pure core).
 *
 * This module contains ONLY the storage algorithm. It has no expo / react-native
 * imports so it can be exercised directly by `node --test` (see
 * test/securestore.node.cjs), which keeps the unit tests on the shipped code
 * instead of a mirror implementation.
 *
 * Layout inside the secure backend (expo-secure-store), per namespace `ns`:
 *   <ns>.meta   -> commit marker: {"v":2,"d":ns,"n":<shards>,"len":<chars>,"crc":<sha256hex>}
 *   <ns>.<i>    -> payload shard i (raw substring, no wrapper)
 *
 * Write protocol (two-phase, `meta` is the single commit point):
 *   1. write shards 0..n-1
 *   2. read every shard back and verify count / length / sha256
 *   3. write the meta shard
 *   4. delete the legacy plaintext copy (only after step 3 succeeded)
 * Any failure before step 3 rolls back the shards that were written and leaves
 * the legacy plaintext untouched. No code path ever writes plaintext back.
 */

export const SHARD_PAYLOAD_MAX_BYTES = 1024;

export type ShardBackend = {
  get(key: string): Promise<string | null>;
  set(key: string, value: string): Promise<void>;
  del(key: string): Promise<void>;
};

/** Read + delete only. The legacy plaintext store is never written to. */
export type LegacyBackend = {
  get(key: string): Promise<string | null>;
  del(key: string): Promise<void>;
};

export type HashFn = (value: string) => Promise<string>;

export type KeyStoreErrorCode =
  | 'unavailable'
  | 'write_failed'
  | 'write_verify_failed'
  | 'read_failed'
  | 'shard_missing'
  | 'shard_corrupt'
  | 'migration_failed'
  | 'legacy_purge_failed'
  | 'invalid_key';

export class KeyStoreError extends Error {
  code: KeyStoreErrorCode;

  constructor(code: KeyStoreErrorCode, message: string) {
    super(message);
    this.name = 'KeyStoreError';
    this.code = code;
  }
}

type Meta = { v: number; d: string; n: number; len: number; crc: string };

export type ShardStoreOptions = {
  ns: string;
  legacyKey: string;
  backend: ShardBackend;
  legacy: LegacyBackend;
  hash: HashFn;
  chunkBytes?: number;
  purgeLegacy?: boolean;
};

export type ShardStore = {
  read(): Promise<string | null>;
  write(value: string): Promise<void>;
  clear(): Promise<void>;
};

function errMessage(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}

/** UTF-8 byte length of a string (no TextEncoder dependency). */
export function utf8Length(s: string): number {
  let n = 0;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c < 0x80) n += 1;
    else if (c < 0x800) n += 2;
    else if (c >= 0xd800 && c <= 0xdbff) {
      n += 4;
      i++;
    } else n += 3;
  }
  return n;
}

/**
 * Split by UTF-8 byte budget without ever cutting a code point in half.
 * Each returned chunk is <= maxBytes bytes, unless a single code point alone
 * exceeds maxBytes (only possible for maxBytes < 4).
 */
export function chunkByUtf8Bytes(s: string, maxBytes: number): string[] {
  if (!Number.isInteger(maxBytes) || maxBytes <= 0) {
    throw new KeyStoreError('invalid_key', 'chunk size must be a positive integer');
  }
  const chunks: string[] = [];
  let cur = '';
  let curBytes = 0;
  for (const ch of s) {
    const b = utf8Length(ch);
    if (cur.length > 0 && curBytes + b > maxBytes) {
      chunks.push(cur);
      cur = '';
      curBytes = 0;
    }
    cur += ch;
    curBytes += b;
  }
  chunks.push(cur);
  return chunks;
}

/** Secure-store keys must match /^[\w.-]+$/ (platform requirement). */
export function assertValidKey(key: string): void {
  if (!/^[\w.-]+$/.test(key)) {
    throw new KeyStoreError('invalid_key', 'invalid secure store key: ' + key);
  }
}

export function metaKeyFor(ns: string): string {
  return ns + '.meta';
}

export function shardKeyFor(ns: string, i: number): string {
  return ns + '.' + i;
}

/** FIFO queue: serialises read/write so concurrent callers cannot interleave. */
export function createSerialQueue(): { run<T>(task: () => Promise<T>): Promise<T> } {
  let tail: Promise<unknown> = Promise.resolve();
  return {
    run<T>(task: () => Promise<T>): Promise<T> {
      const next = tail.then(task, task);
      tail = next.then(
        () => undefined,
        () => undefined,
      );
      return next;
    },
  };
}

export function createShardStore(opts: ShardStoreOptions): ShardStore {
  const { ns, legacyKey, backend, legacy, hash } = opts;
  const chunkBytes = opts.chunkBytes ?? SHARD_PAYLOAD_MAX_BYTES;
  const purgeLegacy = opts.purgeLegacy !== false;
  const metaKey = metaKeyFor(ns);

  async function readMeta(): Promise<Meta | null> {
    const raw = await backend.get(metaKey);
    if (raw == null) return null;
    let m: unknown;
    try {
      m = JSON.parse(raw);
    } catch {
      throw new KeyStoreError('shard_corrupt', 'metadata shard is not valid JSON: ' + ns);
    }
    const meta = m as Meta;
    if (
      !meta ||
      meta.v !== 2 ||
      typeof meta.n !== 'number' ||
      meta.n <= 0 ||
      typeof meta.len !== 'number' ||
      typeof meta.crc !== 'string'
    ) {
      throw new KeyStoreError('shard_corrupt', 'metadata shard is malformed: ' + ns);
    }
    return meta;
  }

  async function deleteShards(n: number): Promise<void> {
    for (let i = 0; i < n; i++) {
      try {
        await backend.del(shardKeyFor(ns, i));
      } catch {
        /* rollback is best effort */
      }
    }
  }

  /** Returns true when a legacy plaintext copy was present and removed. */
  async function purgeLegacyIfPresent(): Promise<boolean> {
    const legacyRaw = await legacy.get(legacyKey);
    if (legacyRaw == null) return false;
    await legacy.del(legacyKey);
    return true;
  }

  async function write(value: string): Promise<void> {
    const chunks = chunkByUtf8Bytes(value, chunkBytes);
    const crc = await hash(value);

    try {
      for (let i = 0; i < chunks.length; i++) {
        const key = shardKeyFor(ns, i);
        assertValidKey(key);
        await backend.set(key, chunks[i]);
      }

      // read-back verification, still before the commit point
      const parts: string[] = [];
      for (let i = 0; i < chunks.length; i++) {
        const got = await backend.get(shardKeyFor(ns, i));
        if (got == null) {
          throw new KeyStoreError('shard_missing', 'shard ' + i + ' missing after write: ' + ns);
        }
        parts.push(got);
      }
      const joined = parts.join('');
      if (joined !== value || (await hash(joined)) !== crc) {
        throw new KeyStoreError('write_verify_failed', 'read-back verification failed: ' + ns);
      }
    } catch (e) {
      await deleteShards(chunks.length);
      if (e instanceof KeyStoreError) throw e;
      throw new KeyStoreError('write_failed', 'failed to write shards for ' + ns + ': ' + errMessage(e));
    }

    // commit point
    const meta: Meta = { v: 2, d: ns, n: chunks.length, len: value.length, crc };
    try {
      assertValidKey(metaKey);
      await backend.set(metaKey, JSON.stringify(meta));
    } catch (e) {
      await deleteShards(chunks.length);
      try {
        await backend.del(metaKey);
      } catch {
        /* best effort */
      }
      throw new KeyStoreError('write_failed', 'failed to commit metadata for ' + ns + ': ' + errMessage(e));
    }

    if (purgeLegacy) {
      try {
        await purgeLegacyIfPresent();
      } catch (e) {
        throw new KeyStoreError(
          'legacy_purge_failed',
          'secure copy committed but legacy plaintext could not be removed: ' + errMessage(e),
        );
      }
    }
  }

  async function read(): Promise<string | null> {
    let meta: Meta | null;
    try {
      meta = await readMeta();
    } catch (e) {
      if (e instanceof KeyStoreError) throw e;
      throw new KeyStoreError('read_failed', 'failed to read metadata for ' + ns + ': ' + errMessage(e));
    }

    if (meta) {
      const parts: string[] = [];
      for (let i = 0; i < meta.n; i++) {
        const got = await backend.get(shardKeyFor(ns, i));
        if (got == null) {
          throw new KeyStoreError('shard_missing', 'missing shard ' + i + ' for ' + ns);
        }
        parts.push(got);
      }
      const joined = parts.join('');
      let ok = joined.length === meta.len;
      if (ok) ok = (await hash(joined)) === meta.crc;
      if (!ok) {
        throw new KeyStoreError('shard_corrupt', 'integrity check failed for ' + ns);
      }
      if (purgeLegacy) {
        try {
          await purgeLegacyIfPresent();
        } catch (e) {
          throw new KeyStoreError(
            'legacy_purge_failed',
            'legacy plaintext could not be removed: ' + errMessage(e),
          );
        }
      }
      return joined;
    }

    // No committed secure copy: migrate the legacy plaintext if present.
    let legacyRaw: string | null;
    try {
      legacyRaw = await legacy.get(legacyKey);
    } catch (e) {
      throw new KeyStoreError('migration_failed', 'failed to read legacy value: ' + errMessage(e));
    }
    if (legacyRaw == null) return null;

    await write(legacyRaw);
    return legacyRaw;
  }

  async function clear(): Promise<void> {
    let n = 0;
    try {
      const meta = await readMeta();
      if (meta) n = meta.n;
    } catch {
      n = 0;
    }
    await deleteShards(n);
    try {
      await backend.del(metaKey);
    } catch {
      /* best effort */
    }
    try {
      await legacy.del(legacyKey);
    } catch {
      /* best effort */
    }
  }

  return { read, write, clear };
}
