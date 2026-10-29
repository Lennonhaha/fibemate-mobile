/**
 * KEM boundary for the mobile client — typed surface.
 *
 * One engine only. See `./engine.js` for why there is no fallback, and `./identity.js`
 * for the one-time rotation of records written before this boundary existed.
 */

import {
  kem,
  KEM_ALGORITHM,
  KEM_VERSION,
  KEM_SIZES,
  KemError,
  InvalidEncapsulationKeyError,
  InvalidDecapsulationKeyError,
  InvalidCiphertextError,
  LegacyKemMaterialError,
  isFipsCapable,
} from './engine.js';
import { ensureFipsIdentity, assertFipsIdentity } from './identity.js';

export type KemVersion = 'v2_fips' | 'v1_legacy';

export type KemKeyPair = {
  publicKey: Uint8Array;
  secretKey: Uint8Array;
};

export type KemEncapsulation = {
  ciphertext: Uint8Array;
  sharedSecret: Uint8Array;
};

export type LegacyKemSource = 'secret_key' | 'stored_identity' | 'session_record' | 'peer_payload';

export type RotationReason = 'missing' | 'unversioned' | 'v1_legacy' | 'not_fips_capable';

export type EnsureResult = {
  raw: string | null;
  rotated: boolean;
  reason: RotationReason | null;
  version: KemVersion | null;
};

export {
  kem,
  KEM_ALGORITHM,
  KEM_VERSION,
  KEM_SIZES,
  KemError,
  InvalidEncapsulationKeyError,
  InvalidDecapsulationKeyError,
  InvalidCiphertextError,
  LegacyKemMaterialError,
  isFipsCapable,
  ensureFipsIdentity,
  assertFipsIdentity,
};
export { toBase64url as uuidToBase64url, fromBase64url as base64urlToUint8 } from './identity.js';
