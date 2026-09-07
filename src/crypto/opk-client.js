/**
 * FIBEMATE OPK Client — One-Time Pre-Key 客户端管理
 * 
 * 职责:
 * 1. 用 Web Crypto API 生成 X25519 密钥对
 * 2. 私钥本地 IndexedDB 保管，公钥上传服务端
 * 3. 自动监控池余量，低于阈值时补充
 * 
 * X3DH 协议: 每个 OPK 一次性使用，防止重放
 * 上传格式: { keyId: "hex16", publicKey: "base64url" }
 */

const OPK_CONFIG = {
  /** 池目标大小 */
  POOL_SIZE: 100,
  /** 低于此值自动补充 */
  MIN_THRESHOLD: 20,
  /** 每次补充数量 */
  BATCH_SIZE: 50,
  /** 本地存储数据库名 */
  DB_NAME: 'fibemate-opk',
  /** 上传 API 路径 */
  UPLOAD_API: '/api/keys/opk/upload',
  /** 查询 API 路径 */
  COUNT_API: '/api/keys/opk/count'
};

// ========================
// X25519 密钥对生成 (Web Crypto)
// ========================

/**
 * 生成一个 X25519 密钥对
 * @returns {{ keyId: string, publicKey: string, privateKey: CryptoKey }}
 */
async function generateOPKKeyPair() {
  const kp = await crypto.subtle.generateKey(
    { name: 'X25519' },
    true,          // extractable: need raw export
    ['deriveBits'] // only needed for ECDH
  );

  // 导出公钥 (raw 32 bytes → base64url)
  const rawPub = await crypto.subtle.exportKey('raw', kp.publicKey);
  const pubB64 = btoa(String.fromCharCode(...new Uint8Array(rawPub)))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

  // 导出私钥 (raw 32 bytes → base64url)
  const rawPriv = await crypto.subtle.exportKey('raw', kp.privateKey);
  const privB64 = btoa(String.fromCharCode(...new Uint8Array(rawPriv)))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

  // keyId: 前 16 字节 SHA-256 → hex
  const keyId = await sha256Hex(rawPub).then(h => h.substring(0, 16));

  return {
    keyId,
    publicKey: pubB64,           // 上传到服务器
    privateKeyRaw: privB64,      // 本地保管
    privateKey: kp.privateKey,   // CryptoKey (不可序列化)
    createdAt: Date.now()
  };
}

/**
 * 批量生成 OPK
 */
async function generateOPKBatch(count = OPK_CONFIG.BATCH_SIZE) {
  const batch = [];
  for (let i = 0; i < count; i++) {
    const opk = await generateOPKKeyPair();
    batch.push(opk);
  }
  return batch;
}

// ========================
// 本地 IndexedDB 存储 (私钥)
// ========================

function openOPKStore() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(OPK_CONFIG.DB_NAME, 1);
    req.onupgradeneeded = () => {
      req.result.createObjectStore('keys', { keyPath: 'keyId' });
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

/**
 * 保存 OPK 私钥到本地
 */
async function storePrivateKeys(opks) {
  const db = await openOPKStore();
  const tx = db.transaction('keys', 'readwrite');
  const store = tx.objectStore('keys');

  for (const opk of opks) {
    store.put({
      keyId: opk.keyId,
      privateKeyRaw: opk.privateKeyRaw,
      createdAt: opk.createdAt
    });
  }

  return new Promise((resolve, reject) => {
    tx.oncomplete = resolve;
    tx.onerror = () => reject(tx.error);
  });
}

/**
 * 获取并删除一个本地 OPK 私钥 (一次性使用)
 */
async function consumeLocalOPK(keyId) {
  const db = await openOPKStore();
  const tx = db.transaction('keys', 'readwrite');
  const store = tx.objectStore('keys');

  const getReq = store.get(keyId);
  return new Promise((resolve, reject) => {
    getReq.onsuccess = () => {
      const record = getReq.result;
      if (record) {
        store.delete(keyId); // 一次性，用完即删
        resolve(record.privateKeyRaw);
      } else {
        resolve(null);
      }
    };
    getReq.onerror = () => reject(getReq.error);
  });
}

/**
 * 当前本地存储的 OPK 数量
 */
async function getLocalOPKCount() {
  const db = await openOPKStore();
  const tx = db.transaction('keys', 'readonly');
  const store = tx.objectStore('keys');
  const req = store.count();
  return new Promise((resolve, reject) => {
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

// ========================
// 服务端上传
// ========================

/**
 * 上传 OPK 公钥到服务端
 * @param {Array} opks - 生成的 OPK 批次
 * @param {string} token - JWT 认证令牌
 */
async function uploadOPKs(opks, token) {
  const payload = {
    oneTimePreKeys: opks.map(opk => ({
      keyId: opk.keyId,
      publicKey: opk.publicKey
    }))
  };

  const resp = await fetch(OPK_CONFIG.UPLOAD_API, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${token}`
    },
    body: JSON.stringify(payload)
  });

  if (!resp.ok) {
    const err = await resp.json().catch(() => ({}));
    throw new Error(`OPK 上传失败: ${resp.status} — ${err.error || '未知错误'}`);
  }

  return resp.json();
}

/**
 * 查询服务端 OPK 数量
 */
async function getServerOPKCount(token) {
  const resp = await fetch(OPK_CONFIG.COUNT_API, {
    headers: { 'Authorization': `Bearer ${token}` }
  });

  if (!resp.ok) throw new Error(`查询 OPK 失败: ${resp.status}`);
  return resp.json();
}

// ========================
// 自动管理
// ========================

/**
 * 检查并自动补充 OPK
 * @param {string} token - JWT 令牌
 * @returns {{ action: string, local: number, server: number }}
 */
async function checkAndRefill(token) {
  const [localCount, serverStatus] = await Promise.all([
    getLocalOPKCount(),
    getServerOPKCount(token).catch(() => ({ available: 0, needsRefill: true }))
  ]);

  const total = Math.min(localCount, serverStatus.available || 0);

  if (total < OPK_CONFIG.MIN_THRESHOLD) {
    console.log(`[OPK-Client] 池余量 ${total}/${OPK_CONFIG.POOL_SIZE}, 自动补充中...`);
    const batch = await generateOPKBatch(OPK_CONFIG.BATCH_SIZE);
    await storePrivateKeys(batch);
    await uploadOPKs(batch, token);

    const newLocal = await getLocalOPKCount();
    console.log(`[OPK-Client] 补充完成: ${newLocal} 个本地, ${serverStatus.available + OPK_CONFIG.BATCH_SIZE} 个服务端`);
    return { action: 'refilled', local: newLocal, server: serverStatus.available + OPK_CONFIG.BATCH_SIZE };
  }

  return { action: 'ok', local: localCount, server: serverStatus.available };
}

/**
 * 初始化 OPK 池 (首次登录时调用)
 */
async function initOPKPool(token) {
  console.log('[OPK-Client] 初始化 OPK 池...');
  const batch = await generateOPKBatch(OPK_CONFIG.POOL_SIZE);
  await storePrivateKeys(batch);
  await uploadOPKs(batch, token);

  const localCount = await getLocalOPKCount();
  console.log(`[OPK-Client] 初始化完成: ${localCount} 个本地 OPK 就绪`);
  return { local: localCount, uploaded: OPK_CONFIG.POOL_SIZE };
}

/**
 * 清理已消费的本地 OPK (服务端已标记 used 的)
 */
async function cleanupConsumedOPKs(token) {
  const db = await openOPKStore();
  const tx = db.transaction('keys', 'readonly');
  const store = tx.objectStore('keys');
  const allKeys = await new Promise((resolve) => {
    const req = store.getAllKeys();
    req.onsuccess = () => resolve(req.result);
  });

  const localCount = allKeys.length;
  const { available } = await getServerOPKCount(token);

  // 如果本地 > 服务端可用数，说明有些已被消费
  // 保守策略：本地只保留 ≤ 服务端可用的数量
  const toDelete = Math.max(0, localCount - available);
  if (toDelete > 0) {
    console.log(`[OPK-Client] 清理 ${toDelete} 个已消费本地私钥`);
    const tx2 = db.transaction('keys', 'readwrite');
    const store2 = tx2.objectStore('keys');
    for (let i = 0; i < toDelete; i++) {
      store2.delete(allKeys[i]);
    }
    await new Promise(r => { tx2.oncomplete = r; });
  }

  return { deleted: toDelete, remaining: Math.min(localCount, available) };
}

// ========================
// 工具函数
// ========================

async function sha256Hex(buffer) {
  const hash = await crypto.subtle.digest('SHA-256', buffer);
  return Array.from(new Uint8Array(hash))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

// ========================
// 导出
// ========================

window.OPKClient = {
  CONFIG: OPK_CONFIG,
  generateOPKKeyPair,
  generateOPKBatch,
  storePrivateKeys,
  consumeLocalOPK,
  getLocalOPKCount,
  uploadOPKs,
  getServerOPKCount,
  checkAndRefill,
  initOPKPool,
  cleanupConsumedOPKs
};

console.log('[OPK-Client] 模块已加载 ✓');
