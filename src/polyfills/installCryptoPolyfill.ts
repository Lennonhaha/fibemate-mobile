/**
 * Pure installer for a WebCrypto-compatible `crypto.getRandomValues`.
 *
 * Why this exists: `sm-crypto`'s SM2 `SecureRandom` takes its entropy from
 * `window.crypto.getRandomValues` (falling back to `globalThis.crypto`) and has
 * NO silent fallback: when neither exists it throws
 * `当前环境不支持 crypto.getRandomValues！` at module load. React Native 0.86
 * ships no global WebCrypto implementation (and this app installs no polyfill),
 * so the entropy source has to be provided explicitly, before any SM2 code is
 * evaluated.
 *
 * This module is deliberately dependency-free (no imports) so it can be unit
 * tested under plain Node via type stripping; the side effect that binds it to
 * `expo-crypto` lives in `src/polyfills/crypto.ts`.
 */

/** Fills `view` with random bytes and returns it. */
export type RandomSource = (view: Uint8Array) => Uint8Array;

/** Minimal structural view of a `globalThis`-like host. */
export type CryptoHost = {
  crypto?: {
    getRandomValues?: unknown;
  };
};

/** WebCrypto quota for a single `getRandomValues` call. */
export const MAX_BYTES_PER_CALL = 65536;

export function hasUsableGetRandomValues(host: CryptoHost): boolean {
  return !!host.crypto && typeof host.crypto.getRandomValues === 'function';
}

function makeGetRandomValues(source: RandomSource) {
  return function getRandomValues<T extends ArrayBufferView>(array: T): T {
    if (!ArrayBuffer.isView(array)) {
      throw new TypeError('getRandomValues: argument must be a typed array');
    }
    const bytes = array.byteLength;
    if (bytes > MAX_BYTES_PER_CALL) {
      throw new RangeError(
        `getRandomValues: requested ${bytes} bytes, quota is ${MAX_BYTES_PER_CALL}`
      );
    }
    const view = new Uint8Array(array.buffer, array.byteOffset, bytes);
    const filled = source(view);
    // Fail closed: a broken/short source must never be accepted silently.
    if (!(filled instanceof Uint8Array) || filled.length !== bytes) {
      throw new Error('getRandomValues: random source returned an invalid buffer');
    }
    view.set(filled);
    return array;
  };
}

/**
 * Installs `getRandomValues` on `host.crypto` when absent.
 *
 * @returns `true` when this call installed it, `false` when a usable
 *   implementation was already present (never overwritten).
 */
export function installCryptoPolyfill(host: CryptoHost, source: RandomSource): boolean {
  const target = hasUsableGetRandomValues(host)
    ? host.crypto!
    : (host.crypto ?? {});
  if (typeof target.getRandomValues === 'function') return false;
  Object.defineProperty(target, 'getRandomValues', {
    value: makeGetRandomValues(source),
    configurable: true,
    writable: true,
    enumerable: true,
  });
  if (!host.crypto) {
    Object.defineProperty(host, 'crypto', {
      value: target,
      configurable: true,
      writable: true,
      enumerable: true,
    });
  }
  return true;
}
