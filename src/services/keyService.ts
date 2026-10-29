/**
 * Key management service for FIBEMATE Mobile.
 * ML-KEM-768 (FIPS 203) via the vendored NTT-domain implementation in `crypto/kem`.
 * SM2 (GB/T 32918) via sm-crypto.
 * expo-crypto for SHA-256 and secure random.
 */

import * as Crypto from 'expo-crypto';
import { kem, ensureFipsIdentity, type EnsureResult } from '../crypto/kem';
import { uuidToBase64url } from '../crypto/kem';
import sm2 from 'sm-crypto/dist/sm2';

export type KeyPair = {
  publicKey: string;
  privateKey: string;
};

export type IdentityMaterial = {
  mlkem: {
    version: string;    // 'v2_fips' for keys written by this build
    publicKey: string;  // base64url, 1184 bytes
    privateKey: string; // base64url
  };
  sm2: {
    publicKey: string;  // hex, 130 chars (uncompressed)
    privateKey: string; // hex, 64 chars
  };
  createdAt: string;
  kemRotatedAt?: string;
};

// ---- SM2 key generation ----

export function generateSM2KeyPair(): KeyPair {
  const kp = sm2.generateKeyPairHex();
  return {
    publicKey: kp.publicKey,   // hex 130 chars
    privateKey: kp.privateKey, // hex 64 chars
  };
}

// ---- ML-KEM-768 key generation ----

async function generateMLKEMKeyPair(): Promise<KeyPair> {
  const kp = kem.generateKeypair();
  // Fail here rather than at handshake time if the engine cannot round-trip its own key.
  kem.assertFipsCapable(kp.secretKey);
  return {
    publicKey: uuidToBase64url(kp.publicKey),
    privateKey: uuidToBase64url(kp.secretKey),
  };
}

// ---- Identity generation ----

export async function generateIdentity(): Promise<IdentityMaterial> {
  const [mlkemKeys, sm2kp] = await Promise.all([
    generateMLKEMKeyPair(),
    Promise.resolve(generateSM2KeyPair()),
  ]);
  return {
    mlkem: { version: kem.version, ...mlkemKeys },
    sm2: sm2kp,
    createdAt: new Date().toISOString(),
  };
}

// ---- Storage helpers ----

export function serializeIdentity(km: IdentityMaterial): string {
  return JSON.stringify({
    mlkem: km.mlkem,
    sm2: km.sm2,
    createdAt: km.createdAt,
    ...(km.kemRotatedAt ? { kemRotatedAt: km.kemRotatedAt } : {}),
  });
}

export function deserializeIdentity(raw: string): IdentityMaterial {
  const obj = JSON.parse(raw);
  return {
    // Records written before the clean break carry no version field; label them as what
    // they are instead of letting callers assume FIPS 203.
    mlkem: { version: obj?.mlkem?.version ?? 'v1_legacy', ...obj?.mlkem },
    sm2: obj.sm2,
    createdAt: obj.createdAt,
    ...(obj.kemRotatedAt ? { kemRotatedAt: obj.kemRotatedAt } : {}),
  };
}

/**
 * Rotates a stored identity to the FIPS 203 engine if needed, persisting the result.
 *
 * `persist` is the caller's storage write; passing it in keeps this module free of the
 * secure-storage backend so it can be tested outside React Native.
 */
export async function rotateIdentityIfNeeded(
  raw: string | null,
  persist: (next: string) => Promise<void>,
  now: () => string = () => new Date().toISOString(),
): Promise<EnsureResult> {
  // `identity.js` is plain CJS, so TypeScript widens `reason`/`version` to `string`.
  // The runtime values are exactly the literals declared by `EnsureResult`.
  const result = ensureFipsIdentity(raw, now) as EnsureResult;
  if (result.rotated && result.raw) {
    await persist(result.raw);
  }
  return result;
}

// ---- Random utilities ----

export async function getSecureRandom(length: number): Promise<Uint8Array> {
  const bytes = await Crypto.getRandomBytesAsync(length);
  return new Uint8Array(bytes);
}

export async function sha256hex(data: Uint8Array): Promise<string> {
  const hex = Array.from(data).map(b => b.toString(16).padStart(2, '0')).join('');
  return Crypto.digestStringAsync(Crypto.CryptoDigestAlgorithm.SHA256, hex);
}
