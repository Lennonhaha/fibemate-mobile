/**
 * Unit tests for src/services/shardStore.ts (PR-B: secure-store sharded key storage).
 *
 * These tests exercise the SHIPPED core module directly (Node >= 22 can require
 * the .ts file via built-in type stripping), so they are not a mirror
 * implementation. CI still runs `npx jest --passWithNoTests`, which ignores this
 * filename on purpose (see test/entropy.node.cjs for the same convention).
 *
 * Run:  node --no-warnings --test test/securestore.node.cjs
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const core = require('../src/services/shardStore.ts');
const {
  createShardStore,
  createSerialQueue,
  chunkByUtf8Bytes,
  utf8Length,
  assertValidKey,
  metaKeyFor,
  shardKeyFor,
  KeyStoreError,
  SHARD_PAYLOAD_MAX_BYTES,
} = core;

const NS = 'fibemate.test.v2';
const LEGACY_KEY = 'fibemate_test_legacy';
const sha256 = (v) => crypto.createHash('sha256').update(v, 'utf8').digest('hex');
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function makeBackend() {
  const b = {
    map: new Map(),
    log: [],
    failSet: null,
    failGet: null,
    failDel: null,
  };
  b.get = async function (k) {
    b.log.push('get:' + k);
    if (b.failGet && b.failGet(k)) throw new Error('backend get failed');
    return b.map.has(k) ? b.map.get(k) : null;
  };
  b.set = async function (k, v) {
    b.log.push('set:' + k);
    if (b.failSet && b.failSet(k, v)) throw new Error('backend set failed');
    b.map.set(k, v);
  };
  b.del = async function (k) {
    b.log.push('del:' + k);
    if (b.failDel && b.failDel(k)) throw new Error('backend del failed');
    b.map.delete(k);
  };
  return b;
}

/** Legacy plaintext store: read + delete only. Note the absence of set(). */
function makeLegacy(init) {
  const l = {
    map: new Map(Object.entries(init || {})),
    log: [],
    failGet: null,
    failDel: null,
  };
  l.get = async function (k) {
    l.log.push('get:' + k);
    if (l.failGet && l.failGet(k)) throw new Error('legacy get failed');
    return l.map.has(k) ? l.map.get(k) : null;
  };
  l.del = async function (k) {
    l.log.push('del:' + k);
    if (l.failDel && l.failDel(k)) throw new Error('legacy del failed');
    l.map.delete(k);
  };
  return l;
}

function mk(opts) {
  const backend = makeBackend();
  const legacy = makeLegacy(opts && opts.legacy);
  const store = createShardStore({
    ns: NS,
    legacyKey: LEGACY_KEY,
    backend,
    legacy,
    hash: sha256,
    chunkBytes: opts && opts.chunkBytes,
    purgeLegacy: opts ? opts.purgeLegacy : undefined,
  });
  return { store, backend, legacy };
}

function mkIdentityJson() {
  return JSON.stringify({
    mlkem: {
      publicKey: 'B'.repeat(1579),
      privateKey: 'A'.repeat(3200),
    },
    sm2: {
      publicKey: '04' + 'c'.repeat(128),
      privateKey: 'd'.repeat(64),
    },
    createdAt: '2026-10-15T00:00:00.000Z',
  });
}

function mkOpkPoolJson(n) {
  const pool = {};
  for (let i = 0; i < n; i++) {
    pool[crypto.createHash('sha256').update('k' + i).digest('hex').slice(0, 16)] = 'e'.repeat(64);
  }
  return JSON.stringify(pool);
}

async function expectCode(promise, code) {
  try {
    await promise;
  } catch (e) {
    assert.ok(e instanceof KeyStoreError, 'expected KeyStoreError, got ' + e);
    assert.equal(e.code, code);
    return e;
  }
  throw new Error('expected rejection with code ' + code + ', but it resolved');
}

// ---------------------------------------------------------------- primitives

test('utf8Length counts UTF-8 bytes for ascii / 2 / 3 / 4 byte code points', () => {
  assert.equal(utf8Length('abc'), 3);
  assert.equal(utf8Length('é'), 2);
  assert.equal(utf8Length('中'), 3);
  assert.equal(utf8Length('😀'), 4);
  assert.equal(utf8Length('a中😀'), 1 + 3 + 4);
});

test('chunkByUtf8Bytes respects the byte budget', () => {
  const chunks = chunkByUtf8Bytes('a'.repeat(3000), 1024);
  assert.equal(chunks.length, 3);
  for (const c of chunks) assert.ok(utf8Length(c) <= 1024);
  assert.equal(chunks.join(''), 'a'.repeat(3000));
});

test('chunkByUtf8Bytes never splits a multi-byte code point', () => {
  const s = '中'.repeat(1000); // 3000 bytes
  const chunks = chunkByUtf8Bytes(s, 1024);
  assert.ok(chunks.length >= 3);
  for (const c of chunks) {
    assert.ok(utf8Length(c) <= 1024, 'chunk over budget: ' + utf8Length(c));
    assert.equal(c, '中'.repeat(c.length), 'code point was split');
  }
  assert.equal(chunks.join(''), s);
});

test('chunkByUtf8Bytes never splits a surrogate pair (4-byte emoji)', () => {
  const s = '😀'.repeat(600); // 2400 bytes
  const chunks = chunkByUtf8Bytes(s, 1024);
  for (const c of chunks) {
    assert.ok(utf8Length(c) <= 1024);
    assert.equal([...c].every((ch) => ch === '😀'), true, 'surrogate pair was split');
  }
  assert.equal(chunks.join(''), s);
});

test('chunkByUtf8Bytes boundary sizes 1023 / 1024 / 1025', () => {
  assert.equal(chunkByUtf8Bytes('a'.repeat(1023), 1024).length, 1);
  assert.equal(chunkByUtf8Bytes('a'.repeat(1024), 1024).length, 1);
  assert.equal(chunkByUtf8Bytes('a'.repeat(1025), 1024).length, 2);
});

test('chunkByUtf8Bytes rejects a non-positive / non-integer budget', async () => {
  await expectCode(
    Promise.resolve().then(() => chunkByUtf8Bytes('x', 0)),
    'invalid_key',
  );
  await expectCode(
    Promise.resolve().then(() => chunkByUtf8Bytes('x', 10.5)),
    'invalid_key',
  );
});

test('chunkByUtf8Bytes keeps a single empty chunk for an empty payload', () => {
  assert.equal(chunkByUtf8Bytes('', 1024).length, 1);
});

test('default shard budget is 1024 bytes (strictly below 2048)', () => {
  assert.equal(SHARD_PAYLOAD_MAX_BYTES, 1024);
  assert.ok(SHARD_PAYLOAD_MAX_BYTES < 2048);
});

test('secure-store keys satisfy the platform charset /^[\\w.-]+$/', () => {
  assertValidKey(metaKeyFor(NS));
  assertValidKey(shardKeyFor(NS, 0));
  assertValidKey(shardKeyFor(NS, 17));
  assert.match(metaKeyFor(NS), /^[\w.-]+$/);
  assert.throws(() => assertValidKey('bad key'), (e) => e.code === 'invalid_key');
  assert.throws(() => assertValidKey('bad#key'), (e) => e.code === 'invalid_key');
});

// ---------------------------------------------------------------- round trips

test('identity payload (5093 B) round-trips across shards', async () => {
  const { store, backend } = mk();
  const value = mkIdentityJson();
  assert.ok(value.length > 5000, 'fixture should be ~5 KB, got ' + value.length);
  await store.write(value);
  const meta = JSON.parse(backend.map.get(metaKeyFor(NS)));
  assert.equal(meta.v, 2);
  assert.ok(meta.n >= 5, 'expected >=5 shards, got ' + meta.n);
  assert.equal(meta.len, value.length);
  assert.equal(meta.crc, sha256(value));
  assert.equal(await store.read(), value);
});

test('OPK pool with 1 / 100 / 200 entries round-trips', async () => {
  for (const n of [1, 100, 200]) {
    const { store, backend } = mk();
    const value = mkOpkPoolJson(n);
    await store.write(value);
    const meta = JSON.parse(backend.map.get(metaKeyFor(NS)));
    assert.equal(meta.n, Math.ceil(value.length / 1024), 'shard count for n=' + n);
    assert.equal(await store.read(), value);
  }
});

test('200-entry pool (~17 KB) needs <= 17 shards and reads back whole', async () => {
  const { store, backend } = mk();
  const value = mkOpkPoolJson(200);
  assert.ok(value.length > 17000, 'fixture should be ~17 KB, got ' + value.length);
  await store.write(value);
  assert.ok(backend.map.get(metaKeyFor(NS)) !== undefined);
  assert.equal(await store.read(), value);
});

test('empty payload round-trips', async () => {
  const { store } = mk();
  await store.write('');
  assert.equal(await store.read(), '');
});

test('a fresh store instance on the same backend reads the committed value (restart)', async () => {
  const { store, backend, legacy } = mk();
  const value = mkIdentityJson();
  await store.write(value);
  const store2 = createShardStore({
    ns: NS,
    legacyKey: LEGACY_KEY,
    backend,
    legacy,
    hash: sha256,
  });
  assert.equal(await store2.read(), value);
});

test('read returns null when neither shards nor legacy exist', async () => {
  const { store } = mk();
  assert.equal(await store.read(), null);
});

// ---------------------------------------------------------------- protocol

test('meta shard is written last (single commit point)', async () => {
  const { store, backend } = mk();
  await store.write(mkIdentityJson());
  const sets = backend.log.filter((l) => l.startsWith('set:'));
  assert.equal(sets[sets.length - 1], 'set:' + metaKeyFor(NS));
  const shardSets = sets.slice(0, -1);
  assert.ok(shardSets.length >= 5);
  shardSets.forEach((s, i) => assert.equal(s, 'set:' + shardKeyFor(NS, i)));
});

test('every shard is read back and verified before the meta commit', async () => {
  const { store, backend } = mk();
  await store.write(mkIdentityJson());
  const metaIdx = backend.log.indexOf('set:' + metaKeyFor(NS));
  const reads = backend.log.slice(0, metaIdx).filter((l) => l.startsWith('get:'));
  assert.ok(reads.length >= 5, 'expected read-back verification, got ' + reads.length);
});

// ---------------------------------------------------------------- migration

test('legacy plaintext is migrated on read, then deleted', async () => {
  const value = mkIdentityJson();
  const { store, backend, legacy } = mk({ legacy: { [LEGACY_KEY]: value } });
  assert.equal(await store.read(), value);
  assert.ok(backend.map.has(metaKeyFor(NS)), 'meta committed');
  assert.equal(legacy.map.has(LEGACY_KEY), false, 'legacy plaintext removed');
  assert.equal(await store.read(), value);
});

test('migration is idempotent (second read does not rewrite shards)', async () => {
  const value = mkIdentityJson();
  const { store, backend } = mk({ legacy: { [LEGACY_KEY]: value } });
  await store.read();
  const setsAfterFirst = backend.log.filter((l) => l.startsWith('set:')).length;
  await store.read();
  const setsAfterSecond = backend.log.filter((l) => l.startsWith('set:')).length;
  assert.equal(setsAfterSecond, setsAfterFirst, 'no extra writes on the second read');
});

test('purgeLegacy:false keeps the legacy copy but still commits secure shards', async () => {
  const value = mkIdentityJson();
  const { store, backend, legacy } = mk({ legacy: { [LEGACY_KEY]: value }, purgeLegacy: false });
  assert.equal(await store.read(), value);
  assert.ok(backend.map.has(metaKeyFor(NS)));
  assert.equal(legacy.map.get(LEGACY_KEY), value, 'legacy retained by operator switch');
});

test('legacy store is only ever read and deleted (no plaintext write API)', async () => {
  const { store, legacy } = mk({ legacy: { [LEGACY_KEY]: mkIdentityJson() } });
  await store.read();
  await store.write('x'.repeat(3000));
  assert.equal(typeof legacy.set, 'undefined', 'legacy backend has no set()');
  const kinds = new Set(legacy.log.map((l) => l.split(':')[0]));
  assert.deepEqual([...kinds].sort(), ['del', 'get']);
});

// ---------------------------------------------------------------- failures

test('shard write failure: write_failed, rollback, no meta, legacy kept', async () => {
  const value = mkIdentityJson();
  const { store, backend, legacy } = mk({ legacy: { [LEGACY_KEY]: value } });
  backend.failSet = (k) => k.endsWith('.2');
  await expectCode(store.write(value), 'write_failed');
  assert.equal(backend.map.size, 0, 'shards rolled back (no leftover keys)');
  assert.equal(legacy.map.get(LEGACY_KEY), value, 'legacy plaintext preserved');
});

test('meta write failure: write_failed and shards rolled back', async () => {
  const { store, backend } = mk();
  backend.failSet = (k) => k.endsWith('.meta');
  await expectCode(store.write(mkIdentityJson()), 'write_failed');
  assert.equal(backend.map.size, 0, 'no shards left behind');
});

test('legacy read failure during migration -> migration_failed (never null)', async () => {
  const { store, legacy } = mk({ legacy: { [LEGACY_KEY]: mkIdentityJson() } });
  legacy.failGet = () => true;
  await expectCode(store.read(), 'migration_failed');
});

test('legacy delete failure -> legacy_purge_failed and the secure copy stays committed', async () => {
  const value = 'z'.repeat(3000);
  const { store, backend, legacy } = mk({ legacy: { [LEGACY_KEY]: value } });
  legacy.failDel = () => true;
  await expectCode(store.read(), 'legacy_purge_failed');
  assert.ok(backend.map.has(metaKeyFor(NS)), 'commit retained');
  assert.equal(legacy.map.get(LEGACY_KEY), value, 'legacy still present');
});

test('missing shard -> shard_missing', async () => {
  const { store, backend } = mk();
  await store.write(mkIdentityJson());
  backend.map.delete(shardKeyFor(NS, 1));
  await expectCode(store.read(), 'shard_missing');
});

test('tampered shard content -> shard_corrupt', async () => {
  const { store, backend } = mk();
  await store.write(mkIdentityJson());
  backend.map.set(shardKeyFor(NS, 1), backend.map.get(shardKeyFor(NS, 1)) + 'X');
  await expectCode(store.read(), 'shard_corrupt');
});

test('truncated shard (length mismatch) -> shard_corrupt', async () => {
  const { store, backend } = mk();
  await store.write(mkIdentityJson());
  const v = backend.map.get(shardKeyFor(NS, 0));
  backend.map.set(shardKeyFor(NS, 0), v.slice(0, v.length - 1));
  await expectCode(store.read(), 'shard_corrupt');
});

test('invalid metadata JSON -> shard_corrupt', async () => {
  const { store, backend } = mk();
  backend.map.set(metaKeyFor(NS), '{not json');
  await expectCode(store.read(), 'shard_corrupt');
});

test('malformed metadata -> shard_corrupt', async () => {
  const { store, backend } = mk();
  backend.map.set(metaKeyFor(NS), JSON.stringify({ v: 2, n: 0 }));
  await expectCode(store.read(), 'shard_corrupt');
});

test('clear() removes shards, meta and legacy', async () => {
  const { store, backend, legacy } = mk({ legacy: { [LEGACY_KEY]: mkIdentityJson() } });
  await store.write(mkIdentityJson());
  await store.clear();
  assert.equal(backend.map.size, 0);
  assert.equal(legacy.map.size, 0);
  assert.equal(await store.read(), null);
});

// ---------------------------------------------------------------- queue

test('serial queue preserves FIFO order and never interleaves', async () => {
  const q = createSerialQueue();
  const order = [];
  const p1 = q.run(async () => {
    order.push('a1');
    await sleep(20);
    order.push('a2');
  });
  const p2 = q.run(async () => {
    order.push('b1');
    await sleep(1);
    order.push('b2');
  });
  await Promise.all([p1, p2]);
  assert.deepEqual(order, ['a1', 'a2', 'b1', 'b2']);
});

test('serial queue still runs the next task after a rejection', async () => {
  const q = createSerialQueue();
  await assert.rejects(q.run(async () => {
    throw new Error('boom');
  }));
  assert.equal(await q.run(async () => 'after'), 'after');
});

// ---------------------------------------------------------------- static audit

test('core module contains no Math.random and no plaintext storage API', () => {
  const src = fs.readFileSync(path.join(__dirname, '..', 'src', 'services', 'shardStore.ts'), 'utf8');
  assert.equal(/Math\s*\.\s*random/.test(src), false, 'Math.random must not appear');
  assert.equal(/AsyncStorage/.test(src), false, 'core must not touch AsyncStorage');
  assert.equal(/legacy\s*\.\s*set\s*\(/.test(src), false, 'core must never write to legacy');
});
