'use strict';

/**
 * Unit tests for src/crypto/entropy.js.
 *
 * Run:  node --test test/
 * (`.cjs` is deliberate: jest's default testMatch — `** /?(*.)+(spec|test).[jt]s?(x)`
 *  — does not match `.cjs`, so the CI step `npx jest --passWithNoTests` never
 *  picks these node:test files up.)
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const entropy = require('../src/crypto/entropy.js');

const ENTROPY_SRC = path.join(__dirname, '..', 'src', 'crypto', 'entropy.js');
const NO_SOURCE = /no cryptographically-secure random source/;

test('success: randomBytes returns exactly the requested byte length', () => {
  for (const n of [1, 8, 16, 32]) {
    const buf = entropy.randomBytes(n);
    assert.ok(buf instanceof Uint8Array, 'expected Uint8Array');
    assert.equal(buf.length, n);
  }
});

test('success: randomHex returns 2 lowercase hex chars per byte', () => {
  assert.equal(entropy.randomHex(1).length, 2);
  const h8 = entropy.randomHex(8);
  assert.equal(h8.length, 16);
  assert.match(h8, /^[0-9a-f]{16}$/);
  assert.equal(entropy.randomHex(32).length, 64);
});

test('success: consecutive calls do not repeat', () => {
  const seen = new Set();
  for (let i = 0; i < 64; i++) seen.add(entropy.randomHex(16));
  assert.equal(seen.size, 64);
});

test('success: at least one provider is reported in Node (webcrypto)', () => {
  const names = entropy.availableProviders();
  assert.ok(Array.isArray(names) && names.length >= 1, 'expected >= 1 provider');
  assert.ok(
    names.includes('globalThis.crypto.getRandomValues'),
    'expected globalThis.crypto in Node, got ' + JSON.stringify(names)
  );
});

test('fail-closed: no provider => throws, never returns a value', () => {
  entropy._setProvidersForTest([]);
  try {
    assert.throws(() => entropy.randomBytes(16), NO_SOURCE);
    assert.throws(() => entropy.randomHex(16), NO_SOURCE);
  } finally {
    entropy._resetProviders();
  }
});

test('fail-closed: a throwing provider is not silently accepted', () => {
  entropy._setProvidersForTest([
    { name: 'broken', fill() { throw new Error('boom'); } },
  ]);
  try {
    assert.throws(() => entropy.randomHex(16), NO_SOURCE);
  } finally {
    entropy._resetProviders();
  }
});

test('fail-closed: a short/partial buffer is rejected', () => {
  entropy._setProvidersForTest([
    { name: 'short', fill() { return new Uint8Array(3); } },
  ]);
  try {
    assert.throws(() => entropy.randomBytes(16), NO_SOURCE);
  } finally {
    entropy._resetProviders();
  }
});

test('input validation: non-positive / non-integer byteLength throws RangeError', () => {
  for (const bad of [0, -1, 1.5, NaN, '8', undefined, null]) {
    assert.throws(() => entropy.randomBytes(bad), RangeError);
  }
});

test('static: entropy.js source contains no Math.random', () => {
  const src = fs.readFileSync(ENTROPY_SRC, 'utf8');
  assert.equal(/Math\s*\.\s*random/.test(src), false, 'entropy.js must not reference Math.random');
});
