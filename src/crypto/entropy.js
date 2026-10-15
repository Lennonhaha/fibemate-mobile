/**
 * FIBEMATE Mobile — centralized cryptographically-secure entropy source.
 *
 * Single authority for randomness in this repo's crypto code. Fail-closed:
 * when no CSPRNG is available this THROWS. There is deliberately no fallback
 * to any non-cryptographic PRNG.
 *
 * Provider priority (first available wins):
 *   1. expo-crypto `getRandomBytes`      — React Native / Hermes (synchronous)
 *   2. globalThis.crypto.getRandomValues — Web, WebWorker, Node >= 19
 *
 * Both APIs are synchronous, so this module's public API is synchronous.
 * `expo-crypto` is resolved lazily (on first use) so that merely requiring
 * this module never throws in a runtime that lacks it (e.g. plain Node tests).
 *
 * Note: identifiers elsewhere in this codebase built from Date.now() are
 * readable labels only — they are NOT a source of entropy.
 */
'use strict';

const PROVIDER = {
  EXPO: 'expo-crypto.getRandomBytes',
  WEB: 'globalThis.crypto.getRandomValues',
};

// Test-only override. null => resolve the real providers lazily.
let _providers = null;

function detectProviders() {
  const list = [];

  // 1) expo-crypto (React Native / Hermes). getRandomBytes is synchronous.
  try {
    // Resolved at call time, never at import time.
    const Crypto = require('expo-crypto');
    if (Crypto && typeof Crypto.getRandomBytes === 'function') {
      list.push({
        name: PROVIDER.EXPO,
        fill(n) {
          const out = Crypto.getRandomBytes(n);
          return out instanceof Uint8Array ? out : new Uint8Array(out);
        },
      });
    }
  } catch (err) {
    // Not resolvable in this runtime (e.g. plain Node). Try the next provider.
  }

  // 2) WebCrypto: Web, WebWorker, Node >= 19.
  try {
    const g = typeof globalThis !== 'undefined' ? globalThis : undefined;
    const c = g && g.crypto;
    if (c && typeof c.getRandomValues === 'function') {
      list.push({
        name: PROVIDER.WEB,
        fill(n) {
          return c.getRandomValues(new Uint8Array(n));
        },
      });
    }
  } catch (err) {
    // Fall through to the fail-closed throw in randomBytes().
  }

  return list;
}

function providers() {
  if (_providers === null) _providers = detectProviders();
  return _providers;
}

function assertByteLength(byteLength) {
  if (!Number.isInteger(byteLength) || byteLength <= 0) {
    throw new RangeError(
      'entropy: byteLength must be a positive integer, got ' + String(byteLength)
    );
  }
}

/**
 * Fill a fresh Uint8Array of `byteLength` bytes from the first available CSPRNG.
 * @throws {RangeError} on invalid input.
 * @throws {Error} when no CSPRNG is available or every provider failed.
 */
function randomBytes(byteLength) {
  assertByteLength(byteLength);
  const list = providers();
  for (let i = 0; i < list.length; i++) {
    try {
      const buf = list[i].fill(byteLength);
      if (buf instanceof Uint8Array && buf.length === byteLength) return buf;
    } catch (err) {
      // Try the next provider — never degrade to a weaker source.
    }
  }
  throw new Error(
    'entropy: no cryptographically-secure random source available (' +
      PROVIDER.EXPO + ' / ' + PROVIDER.WEB +
      '); refusing to fall back to a weak source'
  );
}

/** CSPRNG bytes rendered as lowercase hex (2 chars per byte). */
function randomHex(byteLength) {
  const bytes = randomBytes(byteLength);
  let out = '';
  for (let i = 0; i < bytes.length; i++) {
    out += bytes[i].toString(16).padStart(2, '0');
  }
  return out;
}

module.exports = {
  randomBytes,
  randomHex,
  availableProviders() {
    return providers().map((p) => p.name);
  },
  // ---- Private test seam (NOT part of the public contract) ----
  _setProvidersForTest(list) {
    _providers = list;
  },
  _resetProviders() {
    _providers = null;
  },
};
module.exports.default = module.exports;
