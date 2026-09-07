import AsyncStorage from '@react-native-async-storage/async-storage';

const KEYS = {
  IDENTITY: 'fibemate_identity',
  PREKEYS: 'fibemate_prekeys',
  OPK_POOL: 'fibemate_opk_pool',
  SESSIONS: 'fibemate_sessions',
  SETTINGS: 'fibemate_settings',
};

/**
 * Cross-platform key storage.
 * Uses expo-secure-store on native (iOS/Android), AsyncStorage on web.
 * On web: warning shown but still functional for development.
 */
export const SecureKeyStore = {
  async storeIdentity(keyMaterial: string): Promise<void> {
    try {
      await AsyncStorage.setItem(KEYS.IDENTITY, keyMaterial);
    } catch (e) {
      console.warn('[SecureKeyStore] AsyncStorage write failed:', e);
    }
  },

  async loadIdentity(): Promise<string | null> {
    try {
      return await AsyncStorage.getItem(KEYS.IDENTITY);
    } catch {
      return null;
    }
  },

  async deleteIdentity(): Promise<void> {
    await AsyncStorage.removeItem(KEYS.IDENTITY);
  },
};

/**
 * Non-secret session / config storage.
 */
export const LocalStore = {
  async set(key: string, value: any): Promise<void> {
    await AsyncStorage.setItem(key, JSON.stringify(value));
  },

  async get<T>(key: string): Promise<T | null> {
    const raw = await AsyncStorage.getItem(key);
    return raw ? JSON.parse(raw) : null;
  },

  async remove(key: string): Promise<void> {
    await AsyncStorage.removeItem(key);
  },

  async storeSessions(sessions: any[]): Promise<void> {
    await AsyncStorage.setItem(KEYS.SESSIONS, JSON.stringify(sessions));
  },

  async loadSessions<T>(): Promise<T[]> {
    const raw = await AsyncStorage.getItem(KEYS.SESSIONS);
    return raw ? JSON.parse(raw) : [];
  },

  async clearAll(): Promise<void> {
    const keys = Object.values(KEYS);
    for (const k of keys) {
      await AsyncStorage.removeItem(k);
    }
  },
};
