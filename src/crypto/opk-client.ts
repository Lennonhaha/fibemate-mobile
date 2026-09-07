/**
 * FIBEMATE Mobile — OPK (One-Time Pre-Key) 客户端管理
 *
 * X3DH 协议对口：ML-KEM-768 是 KEM 主线，
 * OPK 层用 X25519 ECDH（Signal/X3DH 标准），
 * 因为 ML-KEM 公钥 1.2KB 不适合做 OPK 池（池大小 x 成本）。
 *
 * 依赖：
 *   - @noble/curves/ed25519 → x25519 （纯 JS，Hermes 兼容）
 *   - expo-crypto → getRandomBytesAsync （Hermes 安全的随机数）
 *   - @react-native-async-storage → 密钥持久化
 */

import { x25519 } from '@noble/curves/ed25519';
import * as Crypto from 'expo-crypto';
import AsyncStorage from '@react-native-async-storage/async-storage';
import { uint8ArrayToHex } from './utils';

// ========================
// 类型定义
// ========================

export type OPKeyPair = {
  keyId: string;         // SHA-256(pub) 前 16 hex
  publicKey: string;     // base64url 43 chars
  privateKeyHex: string; // hex 64 chars
  createdAt: number;     // Date.now()
};

/** OPK 池状态快照 */
export type OPKPoolStatus = {
  local: number;
  uploaded: number;
  needsRefill: boolean;
};

// ========================
// 配置
// ========================

export const OPK_CONFIG = {
  POOL_SIZE: 100,
  MIN_THRESHOLD: 20,
  BATCH_SIZE: 50,
} as const;

const OPK_STORAGE_KEY = 'fibemate_opk_pool';

// ========================
// 工具函数
// ========================

/** Uint8Array → base64url （Hermes 兼容） */
function uint8ArrayToBase64url(arr: Uint8Array): string {
  const bin = Array.from(arr).map(b => String.fromCharCode(b)).join('');
  const b64 = btoa(bin);
  return b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/** hex → Uint8Array */
function hexToUint8Array(hex: string): Uint8Array {
  const arr = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    arr[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }
  return arr;
}

// ========================
// OPK 密钥对生成
// ========================

/**
 * 生成一个 X25519 OPK 密钥对
 * Hermes 兼容：@noble/curves 是纯 JS，不依赖 Web Crypto
 */
export async function generateOPKKeyPair(): Promise<OPKeyPair> {
  // 用 expo-crypto 获取安全随机数（Hermes 下可行）
  const randBytes = await Crypto.getRandomBytesAsync(32);
  const privateKeyBytes = new Uint8Array(randBytes);

  // 衍生公钥
  const publicKeyBytes = x25519.getPublicKey(privateKeyBytes);

  // keyId = SHA-256(pub) 前 16 hex
  const keyIdHex = await Crypto.digestStringAsync(
    Crypto.CryptoDigestAlgorithm.SHA256,
    uint8ArrayToHex(publicKeyBytes),
  );
  const keyId = keyIdHex.substring(0, 16);

  return {
    keyId,
    publicKey: uint8ArrayToBase64url(publicKeyBytes),
    privateKeyHex: uint8ArrayToHex(privateKeyBytes),
    createdAt: Date.now(),
  };
}

/**
 * 批量生成 OPK
 */
export async function generateOPKBatch(count: number = OPK_CONFIG.BATCH_SIZE): Promise<OPKeyPair[]> {
  const batch: OPKeyPair[] = [];
  for (let i = 0; i < count; i++) {
    batch.push(await generateOPKKeyPair());
  }
  return batch;
}

// ========================
// 本地存储（AsyncStorage）
// ========================

/** 保存一批 OPK 私钥到 AsyncStorage */
export async function storeOPKBatch(opks: OPKeyPair[]): Promise<void> {
  const existing = await loadOPKPool();
  for (const opk of opks) {
    existing[opk.keyId] = opk.privateKeyHex;
  }
  await AsyncStorage.setItem(OPK_STORAGE_KEY, JSON.stringify(existing));
}

/** 加载整个 OPK 池 */
export async function loadOPKPool(): Promise<Record<string, string>> {
  const raw = await AsyncStorage.getItem(OPK_STORAGE_KEY);
  if (!raw) return {};
  try {
    return JSON.parse(raw);
  } catch {
    return {};
  }
}

/** 消费并删除一个 OPK 私钥 */
export async function consumeLocalOPK(keyId: string): Promise<string | null> {
  const pool = await loadOPKPool();
  const privHex = pool[keyId];
  if (!privHex) return null;

  delete pool[keyId];
  await AsyncStorage.setItem(OPK_STORAGE_KEY, JSON.stringify(pool));
  return privHex;
}

/** 获取本地 OPK 数量 */
export async function getLocalOPKCount(): Promise<number> {
  const pool = await loadOPKPool();
  return Object.keys(pool).length;
}

/** 清空本地 OPK 池 */
export async function clearOPKPool(): Promise<void> {
  await AsyncStorage.removeItem(OPK_STORAGE_KEY);
}

// ========================
// 服务端通信（待注册后端就绪）
// ========================

export type OPKServiceConfig = {
  baseUrl: string;       // API 基地址，如 http://8.156.77.68
  getToken: () => Promise<string | null>;
};

/**
 * 上传 OPK 公钥到服务端
 */
export async function uploadOPKs(
  opks: OPKeyPair[],
  config: OPKServiceConfig,
): Promise<{ success: boolean; uploaded: number }> {
  const token = await config.getToken();
  if (!token) {
    console.warn('[OPK] 无 JWT 令牌，跳过上传');
    return { success: false, uploaded: 0 };
  }

  const payload = {
    oneTimePreKeys: opks.map(opk => ({
      keyId: opk.keyId,
      publicKey: opk.publicKey,
    })),
  };

  try {
    const resp = await fetch(`${config.baseUrl}/api/keys/opk/upload`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`,
      },
      body: JSON.stringify(payload),
    });

    if (!resp.ok) {
      const err = await resp.json().catch(() => ({}));
      console.warn(`[OPK] 上传失败 (${resp.status}): ${err.error || ''}`);
      return { success: false, uploaded: 0 };
    }

    const data = await resp.json();
    console.log(`[OPK] 上传成功: ${data.uploaded} 个`);
    return { success: true, uploaded: data.uploaded };
  } catch (err) {
    console.warn('[OPK] 上传网络错误:', err);
    return { success: false, uploaded: 0 };
  }
}

/**
 * 查询服务端 OPK 数量
 */
export async function getServerOPKCount(config: OPKServiceConfig): Promise<number> {
  const token = await config.getToken();
  if (!token) return 0;

  try {
    const resp = await fetch(`${config.baseUrl}/api/keys/opk/count`, {
      headers: { 'Authorization': `Bearer ${token}` },
    });
    if (!resp.ok) return 0;
    const data = await resp.json();
    return data.available || 0;
  } catch {
    return 0;
  }
}

// ========================
// 自动管理循环
// ========================

/**
 * 初始化 OPK 池（首次登录 / 注册后调用）
 * 生成 POOL_SIZE 个 OPK，本地存储 + 服务端上传
 */
export async function initOPKPool(config?: OPKServiceConfig): Promise<OPKPoolStatus> {
  console.log('[OPK] 初始化池...');
  const batch = await generateOPKBatch(OPK_CONFIG.POOL_SIZE);
  await storeOPKBatch(batch);

  let uploaded = 0;
  if (config) {
    const result = await uploadOPKs(batch, config);
    if (result.success) uploaded = result.uploaded;
  }

  const local = await getLocalOPKCount();
  console.log(`[OPK] 初始化完成：${local} 个本地`);
  return { local, uploaded, needsRefill: false };
}

/**
 * 检查并补充 OPK 池（每次 App 启动 / 定时调用）
 */
export async function checkAndRefill(config?: OPKServiceConfig): Promise<OPKPoolStatus> {
  const localCount = await getLocalOPKCount();
  let serverCount = 0;

  if (config) {
    serverCount = await getServerOPKCount(config);
  }

  const effective = Math.min(localCount, config ? serverCount : localCount);
  const needsRefill = effective < OPK_CONFIG.MIN_THRESHOLD;

  if (!needsRefill) {
    return { local: localCount, uploaded: serverCount, needsRefill: false };
  }

  console.log(`[OPK] 余量 ${effective}/${OPK_CONFIG.POOL_SIZE}，补充中...`);
  const batch = await generateOPKBatch(OPK_CONFIG.BATCH_SIZE);
  await storeOPKBatch(batch);

  let uploaded = serverCount;
  if (config) {
    const result = await uploadOPKs(batch, config);
    if (result.success) uploaded = serverCount + result.uploaded;
  }

  const newLocal = await getLocalOPKCount();
  console.log(`[OPK] 补充完成：${newLocal} 本地`);
  return { local: newLocal, uploaded, needsRefill: false };
}

/**
 * 发起会话时：消费一个本地 OPK 私钥
 * @returns privateKey hex string
 */
export async function prepareOPKForSession(keyId: string): Promise<string | null> {
  return consumeLocalOPK(keyId);
}
