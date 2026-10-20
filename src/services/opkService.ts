/**
 * One-time pre-key service (#68).
 *
 * Wires the pure pool rules in `opkPool.ts` to secure storage and SM2 key
 * generation. Private halves are written only to SecureOPKStore (sharded over
 * expo-secure-store); the registration client receives public halves only.
 */

import { SecureOPKStore } from './storage';
import { generateSM2KeyPair } from './keyService';
import { parsePool, publicKeys, refillPool } from './opkPool';
import type { OpkEntry } from './opkPool';

/** Server keeps a Set per user and consumes one key per fetch. */
export const OPK_TARGET = 5;

export async function ensureOpkPool(target: number = OPK_TARGET): Promise<string[]> {
  const raw = await SecureOPKStore.loadPool();
  const pool = parsePool(raw);
  const next = refillPool(pool, target, generateSM2KeyPair);
  if (next.length !== pool.length) {
    await SecureOPKStore.savePool(JSON.stringify(next));
  }
  return publicKeys(next);
}

/** Test seam: the pool as stored, private halves included. */
export async function loadPoolEntries(): Promise<OpkEntry[]> {
  return parsePool(await SecureOPKStore.loadPool());
}
