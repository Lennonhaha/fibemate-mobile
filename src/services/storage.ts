import AsyncStorage from '@react-native-async-storage/async-storage';
import * as Crypto from 'expo-crypto';
import * as SecureStore from 'expo-secure-store';
import { Platform } from 'react-native';

import { createSerialQueue, createShardStore, KeyStoreError } from './shardStore';
import type { LegacyBackend, ShardBackend, ShardStore } from './shardStore';

export { KeyStoreError };

/*
 * Policy: AsyncStorage holds non-secret configuration only. Anything that is
 * key material -- identity, one-time pre-keys, and especially ratchet/session
 * state -- goes through SecureKeyStore / SecureOPKStore, which are sharded
 * over expo-secure-store. There is deliberately no session-blob API in this
 * module: a double-ratchet store must be built on the secure path, not on
 * plaintext AsyncStorage, and #76 tracks that work.
 */

const KEYS = {
  IDENTITY: 'fibemate_identity',
  PREKEYS: 'fibemate_prekeys',
  OPK_POOL: 'fibemate_opk_pool',
  SETTINGS: 'fibemate_settings',
};

/**
 * Cross-platform secure storage for key material (identity + OPK pool).
 *
 * Key material is persisted ONLY through expo-secure-store (iOS Keychain /
 * Android Keystore via the expo-secure-store config plugin), split into shards
 * of <= CHUNK_BYTES bytes because the platform has historically refused large
 * single values. The metadata shard is the single commit point of a write.
 *
 * There is NO plaintext fallback: the legacy AsyncStorage keys are read once to
 * migrate existing installs and are deleted afterwards, and no code path in
 * this module writes key material to AsyncStorage.
 *
 * Web is not supported by expo-secure-store (its web module is an empty object),
 * so on web secrets are kept in memory only and never persisted. As a result a
 * web page reload loses the identity; that is the intended fail-closed trade-off.
 */
const NS = {
  IDENTITY: 'fibemate.identity.v2',
  OPK: 'fibemate.opk.v2',
};

/** Legacy plaintext keys: read + delete only, never written again. */
const LEGACY = {
  IDENTITY: KEYS.IDENTITY,
  OPK: KEYS.OPK_POOL,
};

/**
 * Build-time switch. When false the legacy plaintext copy is left in place after
 * a successful migration (incident response only). It does NOT enable any
 * runtime fallback to plaintext storage.
 */
const PURGE_LEGACY_AFTER_MIGRATION = true;

/** Shard payload budget in bytes (strictly below the ~2048 platform limit). */
const CHUNK_BYTES = 1024;

// ---- backends ----

const memory = new Map<string, string>();

const memoryShardBackend: ShardBackend = {
  async get(key) {
    return memory.has(key) ? (memory.get(key) as string) : null;
  },
  async set(key, value) {
    memory.set(key, value);
  },
  async del(key) {
    memory.delete(key);
  },
};

const secureShardBackend: ShardBackend = {
  async get(key) {
    const value = await SecureStore.getItemAsync(key);
    return value ?? null;
  },
  async set(key, value) {
    await SecureStore.setItemAsync(key, value);
  },
  async del(key) {
    await SecureStore.deleteItemAsync(key);
  },
};

const legacyBackend: LegacyBackend = {
  async get(key) {
    return await AsyncStorage.getItem(key);
  },
  async del(key) {
    await AsyncStorage.removeItem(key);
  },
};

const hash = (value: string): Promise<string> =>
  Crypto.digestStringAsync(Crypto.CryptoDigestAlgorithm.SHA256, value);

// ---- lazy store resolution ----

let backendOverride: ShardBackend | null = null;
let storesPromise: Promise<{ identity: ShardStore; opk: ShardStore }> | null = null;

async function resolveBackend(): Promise<ShardBackend> {
  if (backendOverride) return backendOverride;
  if (Platform.OS === 'web') return memoryShardBackend;
  const available = await SecureStore.isAvailableAsync();
  if (!available) {
    throw new KeyStoreError('unavailable', 'secure storage is not available on this device');
  }
  return secureShardBackend;
}

function stores(): Promise<{ identity: ShardStore; opk: ShardStore }> {
  if (!storesPromise) {
    storesPromise = (async () => {
      const backend = await resolveBackend();
      return {
        identity: createShardStore({
          ns: NS.IDENTITY,
          legacyKey: LEGACY.IDENTITY,
          backend,
          legacy: legacyBackend,
          hash,
          chunkBytes: CHUNK_BYTES,
          purgeLegacy: PURGE_LEGACY_AFTER_MIGRATION,
        }),
        opk: createShardStore({
          ns: NS.OPK,
          legacyKey: LEGACY.OPK,
          backend,
          legacy: legacyBackend,
          hash,
          chunkBytes: CHUNK_BYTES,
          purgeLegacy: PURGE_LEGACY_AFTER_MIGRATION,
        }),
      };
    })();
    storesPromise.catch(() => {
      storesPromise = null;
    });
  }
  return storesPromise;
}

/** All key-material access is serialised to avoid interleaved read/write. */
const queue = createSerialQueue();

export const SecureKeyStore = {
  async storeIdentity(keyMaterial: string): Promise<void> {
    const s = await stores();
    await queue.run(() => s.identity.write(keyMaterial));
  },

  async loadIdentity(): Promise<string | null> {
    const s = await stores();
    return queue.run(() => s.identity.read());
  },

  async deleteIdentity(): Promise<void> {
    const s = await stores();
    await queue.run(() => s.identity.clear());
  },
};

export const SecureOPKStore = {
  async savePool(poolJson: string): Promise<void> {
    const s = await stores();
    await queue.run(() => s.opk.write(poolJson));
  },

  async loadPool(): Promise<string | null> {
    const s = await stores();
    return queue.run(() => s.opk.read());
  },

  async deletePool(): Promise<void> {
    const s = await stores();
    await queue.run(() => s.opk.clear());
  },
};

// ---- test seams (not used by production code paths) ----

export function _setBackendForTest(backend: ShardBackend | null): void {
  backendOverride = backend;
  storesPromise = null;
}

export function _resetStoresForTest(): void {
  backendOverride = null;
  storesPromise = null;
  memory.clear();
}

/**
 * Non-secret session / config storage.
 *
 * Removed in #76. This used to expose `storeSessions` / `loadSessions`, which
 * wrote session state as JSON to plaintext AsyncStorage. It had no callers,
 * and the double-ratchet store that will need it is expected to carry message
 * keys, so keeping the shape around was a loaded gun rather than a
 * convenience. Non-secret configuration belongs in a dedicated config module
 * with no session-shaped API; secrets belong in SecureKeyStore.
 */
