'use strict';

/**
 * Tests for the one-time pre-key pool (#68) plus source-level guards.
 *
 * Run:  node --no-warnings --test test/*.node.cjs
 *
 * `opkPool.ts` is pure and loads under plain Node. `opkService.ts` and
 * `MessageScreen.tsx` pull in expo / react-native, so their wiring is asserted
 * against the source text instead of being imported.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const { refillPool, parsePool, publicKeys, isOpkEntry } = require('../src/services/opkPool.ts');

const SRC = path.join(__dirname, '..', 'src');
const read = (p) => fs.readFileSync(path.join(SRC, p), 'utf8');

function key(n) {
  return {
    publicKey: '04' + String(n).padStart(2, '0').repeat(64),
    privateKey: String(n).padStart(2, '0').repeat(32),
  };
}

test('refillPool grows to the target and keeps existing entries', () => {
  const existing = [key(1), key(2)];
  let n = 10;
  const pool = refillPool(existing, 5, () => key(n++));
  assert.equal(pool.length, 5);
  assert.deepEqual(pool.slice(0, 2), existing);
  assert.equal(publicKeys(pool).length, 5);
});

test('refillPool never shortens a pool above the target', () => {
  const existing = [key(1), key(2), key(3)];
  const pool = refillPool(existing, 2, () => key(9));
  assert.deepEqual(pool, existing);
});

test('refillPool skips duplicate public keys', () => {
  const existing = [key(1)];
  const pool = refillPool(existing, 3, () => key(1));
  assert.equal(pool.length, 1, 'a constant generator must not add duplicates');
});

test('refillPool terminates on a constant generator instead of looping', () => {
  const pool = refillPool([], 4, () => key(7));
  assert.equal(pool.length, 1);
});

test('refillPool rejects malformed entries from the generator', () => {
  const pool = refillPool([], 2, () => ({ publicKey: '', privateKey: 'x' }));
  assert.equal(pool.length, 0);
});

test('parsePool drops malformed rows and survives junk', () => {
  assert.deepEqual(parsePool(null), []);
  assert.deepEqual(parsePool('not json'), []);
  assert.deepEqual(parsePool('{"a":1}'), []);
  const good = key(1);
  assert.deepEqual(parsePool(JSON.stringify([good, { publicKey: 'x' }, null, 5])), [good]);
  assert.equal(isOpkEntry(good), true);
});

test('MessageScreen uploads generated pre-keys, not the identity key', () => {
  const src = read('screens/MessageScreen.tsx');
  assert.ok(!src.includes('opks = [id.sm2.publicKey]'), 'identity key must not be uploaded as an OPK');
  assert.ok(src.includes('ensureOpkPool()'), 'the pool must be filled before upload');
});

test('opkService stores private halves and returns public halves only', () => {
  const src = read('services/opkService.ts');
  assert.ok(src.includes('SecureOPKStore.savePool'), 'private pre-keys must go to the secure store');
  assert.ok(src.includes('publicKeys(next)'), 'only public halves may be returned');
});

test('storage.ts has no session blob API on AsyncStorage (#76)', () => {
  const src = read('services/storage.ts');
  // Prose may mention the removed names; the guard is about declarations and
  // the storage key, not about comments explaining why they are gone.
  assert.ok(!/fibemate_sessions/.test(src), 'the sessions AsyncStorage key must be gone');
  assert.ok(!/KEYS\.SESSIONS/.test(src), 'KEYS.SESSIONS must be gone');
  assert.ok(!/async\s+storeSessions\s*\(/.test(src), 'storeSessions must be gone');
  assert.ok(!/async\s+loadSessions\s*\(/.test(src), 'loadSessions must be gone');
  assert.ok(src.includes('SecureKeyStore'), 'the policy points at the secure path');
});

test('no source file references LocalStore any more (#76)', () => {
  const walk = (dir) =>
    fs.readdirSync(dir, { withFileTypes: true }).flatMap((e) => {
      const p = path.join(dir, e.name);
      if (e.isDirectory()) return walk(p);
      return /\.(ts|tsx)$/.test(e.name) ? [p] : [];
    });
  const offenders = walk(SRC).filter((f) => fs.readFileSync(f, 'utf8').includes('LocalStore'));
  assert.deepEqual(offenders, []);
});
