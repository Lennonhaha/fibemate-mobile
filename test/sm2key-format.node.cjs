'use strict';

/**
 * Unit tests for src/services/sm2KeyFormat.ts, plus source-level guards that
 * the registration client keeps using it (#68 — SM2 private-key material must
 * never be transmitted, cached or encrypted to as if it were a public key).
 *
 * Run:  node --no-warnings --test test/*.node.cjs
 * (`.cjs` is deliberate: it is outside jest's default testMatch, and these are
 *  node:test files. regClient.ts itself is not imported here — it pulls in
 *  react-native / expo modules that do not load under plain Node — so the
 *  client-side wiring is asserted against its source text.)
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const { isSm2PublicKeyHex, isSm2PrivateKeyHex } = require('../src/services/sm2KeyFormat.ts');

const SRC = path.join(__dirname, '..', 'src');
const read = (p) => fs.readFileSync(path.join(SRC, p), 'utf8');

// Shapes only: a 130-hex uncompressed point and a 64-hex scalar. The values are
// throwaway; what matters is the shape the client has to tell apart.
const PUBLIC_KEY_HEX = '04' + '1Ab2'.repeat(32); // 2 + 128 = 130 hex, mixed case
const PRIVATE_KEY_HEX = 'f0e1d2c3'.repeat(8); // 64 hex

test('accepts an uncompressed SM2 public point (04 || X || Y, 130 hex)', () => {
  assert.equal(PUBLIC_KEY_HEX.length, 130);
  assert.ok(isSm2PublicKeyHex(PUBLIC_KEY_HEX));
  assert.ok(isSm2PublicKeyHex('04' + 'a'.repeat(128)));
  assert.ok(isSm2PublicKeyHex('04' + 'F'.repeat(128)), 'uppercase hex is still hex');
});

test('rejects a 64-hex private scalar as a public key', () => {
  assert.equal(PRIVATE_KEY_HEX.length, 64);
  assert.ok(isSm2PrivateKeyHex(PRIVATE_KEY_HEX), 'fixture really is a private-key shape');
  assert.equal(isSm2PublicKeyHex(PRIVATE_KEY_HEX), false);
  assert.equal(isSm2PrivateKeyHex(PUBLIC_KEY_HEX), false, 'the two shapes stay disjoint');
});

test('rejects near-miss shapes', () => {
  const bad = [
    '',                                  // empty
    '04' + 'a'.repeat(126),              // one byte short
    '04' + 'a'.repeat(130),              // one byte long
    '05' + 'a'.repeat(128),              // not an uncompressed-point tag
    '0x' + 'a'.repeat(128),              // 0x prefix
    'a'.repeat(63),                      // scalar one nibble short
    'a'.repeat(65),                      // scalar one nibble long
    'A'.repeat(64),                      // uppercase scalar is not a point either
    'sGVsbG8_'.repeat(6),                // base64url, like the x25519 OPK format
    '04' + 'a'.repeat(127) + ' ',        // trailing space
    ' 04' + 'a'.repeat(128),             // leading space
    undefined,
    null,
    42,
    {},
    [],
  ];
  for (const v of bad) {
    assert.equal(isSm2PublicKeyHex(v), false, `must reject: ${JSON.stringify(v)}`);
  }
});

test('regClient.ts registers the SM2 public key and never reads the private one', () => {
  const src = read('services/regClient.ts');
  assert.match(src, /sm2\?\.publicKey/, 'register() must read sm2.publicKey');
  assert.equal(/sm2\s*\??\.\s*privateKey/.test(src), false, 'regClient must not touch sm2.privateKey at all');
  const uses = src.match(/isSm2PublicKeyHex/g) || [];
  assert.ok(uses.length >= 3, `expected the validator to be imported and used at both ends, saw ${uses.length}`);
});

test('regClient.ts rejects a lookup result that is not an SM2 public key', () => {
  const src = read('services/regClient.ts');
  const lookup = src.slice(src.indexOf('export async function lookupUser'));
  assert.match(lookup, /if \(!isSm2PublicKeyHex\(r\.identityKey\)\)/, 'lookupUser must validate the peer key');
  assert.match(lookup, /throw new Error/, 'lookupUser must fail closed, not return an unusable key');
});

test('MessageScreen never falls back to the local key when encrypting', () => {
  const src = read('screens/MessageScreen.tsx');
  assert.equal(
    /recipientPubKeyCache\s*\|\|\s*myPubKey/.test(src),
    false,
    'the `recipientPubKeyCache || myPubKey` fallback encrypts to ourselves; it must stay removed'
  );
  assert.match(src, /if \(!recipientPubKeyCache\)/, 'the send path must block when there is no peer key');
  assert.equal(/setMyPubKey/.test(src), false, 'the unused myPubKey state is gone');
});
