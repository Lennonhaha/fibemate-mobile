'use strict';

/**
 * Unit tests for src/polyfills/installCryptoPolyfill.ts (+ the side-effect wiring
 * in src/polyfills/crypto.ts and its position in index.ts).
 *
 * Run:  node --test test/*.node.cjs
 * (`.cjs` is deliberate: jest's default testMatch does not match `.cjs`, so the
 * old `npx jest --passWithNoTests` step never picked these node:test files up.)
 *
 * Context: `sm-crypto@0.5.7`'s SM2 `SecureRandom` needs
 * `window.crypto.getRandomValues` / `globalThis.crypto.getRandomValues` and
 * throws when neither exists (no silent Math.random fallback). React Native
 * provides neither, so the app must install its own.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const { installCryptoPolyfill, hasUsableGetRandomValues, MAX_BYTES_PER_CALL } = require(
  '../src/polyfills/installCryptoPolyfill.ts'
);

const ROOT = path.join(__dirname, '..');
const SRC_POLYFILL = path.join(ROOT, 'src', 'polyfills', 'crypto.ts');
const SRC_INSTALLER = path.join(ROOT, 'src', 'polyfills', 'installCryptoPolyfill.ts');
const SRC_INDEX = path.join(ROOT, 'index.ts');

/** Deterministic stand-in for expo-crypto's native source. */
const countingSource = (counter) => (view) => {
  for (let i = 0; i < view.length; i++) view[i] = (i * 37 + 11) % 256;
  counter.calls++;
  counter.bytes += view.length;
  return view;
};

test('install: defines getRandomValues on a host without crypto', () => {
  const host = {};
  const counter = { calls: 0, bytes: 0 };
  assert.equal(hasUsableGetRandomValues(host), false);
  assert.equal(installCryptoPolyfill(host, countingSource(counter)), true);
  assert.equal(hasUsableGetRandomValues(host), true);
  assert.equal(typeof host.crypto.getRandomValues, 'function');
});

test('install: is idempotent and keeps the first implementation', () => {
  const host = {};
  installCryptoPolyfill(host, countingSource({ calls: 0, bytes: 0 }));
  const first = host.crypto.getRandomValues;
  assert.equal(installCryptoPolyfill(host, countingSource({ calls: 0, bytes: 0 })), false);
  assert.equal(host.crypto.getRandomValues, first);
});

test('install: never overwrites an existing usable getRandomValues (web)', () => {
  const real = (a) => a;
  const host = { crypto: { getRandomValues: real, subtle: { tag: 'keep-me' } } };
  assert.equal(hasUsableGetRandomValues(host), true);
  assert.equal(installCryptoPolyfill(host, countingSource({ calls: 0, bytes: 0 })), false);
  assert.equal(host.crypto.getRandomValues, real);
  assert.deepEqual(host.crypto.subtle, { tag: 'keep-me' });
});

test('install: patches an existing crypto object without dropping its fields', () => {
  const host = { crypto: { randomUUID: () => 'x' } };
  assert.equal(installCryptoPolyfill(host, countingSource({ calls: 0, bytes: 0 })), true);
  assert.equal(host.crypto.randomUUID(), 'x');
  assert.equal(typeof host.crypto.getRandomValues, 'function');
});

test('behaviour: fills the passed view, returns that same view', () => {
  const host = {};
  const counter = { calls: 0, bytes: 0 };
  installCryptoPolyfill(host, countingSource(counter));
  const buf = new Uint8Array(32);
  const out = host.crypto.getRandomValues(buf);
  assert.equal(out, buf, 'must return the array it was given');
  assert.deepEqual(Array.from(buf), Array.from({ length: 32 }, (_, i) => (i * 37 + 11) % 256));
  assert.deepEqual(counter, { calls: 1, bytes: 32 });
});

test('behaviour: byte view of a Uint32Array is filled (2 words => 8 bytes)', () => {
  const host = {};
  const counter = { calls: 0, bytes: 0 };
  installCryptoPolyfill(host, countingSource(counter));
  const words = new Uint32Array(2);
  const out = host.crypto.getRandomValues(words);
  assert.equal(out, words);
  assert.equal(counter.bytes, 8);
  assert.notEqual(words[0], 0);
});

test('fail-closed: a short or non-Uint8Array source is rejected', () => {
  const hostShort = {};
  installCryptoPolyfill(hostShort, () => new Uint8Array(3));
  assert.throws(() => hostShort.crypto.getRandomValues(new Uint8Array(16)), /invalid buffer/);

  const hostNotU8 = {};
  installCryptoPolyfill(hostNotU8, (v) => Array.from(v));
  assert.throws(() => hostNotU8.crypto.getRandomValues(new Uint8Array(4)), /invalid buffer/);
});

test('input validation: non-typed-array argument throws TypeError', () => {
  const host = {};
  installCryptoPolyfill(host, countingSource({ calls: 0, bytes: 0 }));
  for (const bad of [new ArrayBuffer(8), [1, 2], 42, undefined, null, '8']) {
    assert.throws(() => host.crypto.getRandomValues(bad), TypeError);
  }
});

test('input validation: over-quota request throws RangeError', () => {
  const host = {};
  installCryptoPolyfill(host, countingSource({ calls: 0, bytes: 0 }));
  assert.throws(
    () => host.crypto.getRandomValues(new Uint8Array(MAX_BYTES_PER_CALL + 1)),
    RangeError
  );
});

test('static: installer source contains no Math.random', () => {
  const src = fs.readFileSync(SRC_INSTALLER, 'utf8');
  assert.equal(/Math\s*\.\s*random/.test(src), false);
});

test('static: the side-effect module is backed by expo-crypto', () => {
  const src = fs.readFileSync(SRC_POLYFILL, 'utf8');
  assert.match(src, /import \* as Crypto from 'expo-crypto'/);
  assert.match(src, /installCryptoPolyfill\(globalThis/);
  assert.match(src, /Crypto\.getRandomValues\(/);
  assert.equal(/Math\s*\.\s*random/.test(src), false);
});

test('static: index.ts imports the polyfill first, before expo/App', () => {
  const imports = fs
    .readFileSync(SRC_INDEX, 'utf8')
    .split('\n')
    .filter((l) => /^\s*import\s/.test(l));
  assert.ok(imports.length >= 3, 'expected at least 3 import lines, got ' + imports.length);
  assert.match(imports[0], /^import '\.\/src\/polyfills\/crypto';/, 'first import was: ' + imports[0]);
  assert.ok(
    imports.findIndex((l) => /from '\.\/App'/.test(l)) > 0,
    'App must be imported after the polyfill'
  );
});
