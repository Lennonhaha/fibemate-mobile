/**
 * Side-effect module: gives the app runtime a WebCrypto-compatible
 * `globalThis.crypto.getRandomValues`, backed by the native CSPRNG via
 * `expo-crypto`.
 *
 * Imported FIRST by `index.ts`, so it installs before `App` (and therefore
 * before the screens that import `sm-crypto/dist/sm2`) are evaluated. Without
 * it, `sm-crypto`'s SM2 `SecureRandom` has no entropy source on device.
 *
 * On web the browser already provides `crypto.getRandomValues`, so
 * `installCryptoPolyfill` leaves it untouched.
 */

import * as Crypto from 'expo-crypto';
import { installCryptoPolyfill } from './installCryptoPolyfill';

installCryptoPolyfill(globalThis, (view: Uint8Array): Uint8Array => Crypto.getRandomValues(view));
