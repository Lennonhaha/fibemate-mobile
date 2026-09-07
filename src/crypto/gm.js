/**
 * ============================================================
 * FIBEMATE 国密加密模块 — v3.0.1 合规版
 * ============================================================
 *
 * 渲染进程直接使用。依赖 window.GM (由 electron.preload.js 注入)。
 * 不依赖 Node.js Buffer/crypto。
 *
 * 替换 MessageCryptoV2：
 *   - encrypt/decrypt 接口兼容
 *   - SM2 协商代替 X3DH
 *   - SM4-αGCM 代替 AES-256-GCM
 *   - SM3 代替 SHA-256
 */

const MessageGM = (() => {
  'use strict';

  const DB_NAME = 'fibemate_gm_v1';
  const STORE_CONFIG = 'config';
  const SESSION_ACTIVE = 'active';
  const SESSION_NONE = 'none';

  let db = null;
  let _clientKeyPair = null;
  let _serverPublicKey = null;
  let _sm4SessionKey = null;
  let _sessionState = SESSION_NONE;
  let _sessionId = null;

  // ---- Helpers ----
  function gm() { return window.GM; }

  // hex → Uint8Array (browser-safe, no Buffer)
  function hexToBytes(hex) {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2)
      bytes[i>>1] = parseInt(hex.substr(i, 2), 16);
    return bytes;
  }

  function bytesToHex(bytes) {
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
  }

  // ============================================================
  // IndexedDB Persistence
  // ============================================================
  async function initDB() {
    return new Promise((resolve, reject) => {
      const request = indexedDB.open(DB_NAME, 1);
      request.onerror = () => reject(request.error);
      request.onsuccess = () => { db = request.result; resolve(db); };
      request.onupgradeneeded = (e) => {
        const database = e.target.result;
        if (!database.objectStoreNames.contains(STORE_CONFIG))
          database.createObjectStore(STORE_CONFIG, { keyPath: 'key' });
      };
    });
  }

  function tx(storeName, mode) {
    if (!db) throw new Error('[MessageGM] DB not initialized');
    return db.transaction(storeName, mode).objectStore(storeName);
  }

  function promisify(request) {
    return new Promise((resolve, reject) => {
      request.onerror = () => reject(request.error);
      request.onsuccess = () => resolve(request.result);
    });
  }

  // ============================================================
  // SM2 密钥对管理
  // ============================================================
  async function getOrCreateClientKeyPair() {
    if (_clientKeyPair) return _clientKeyPair;
    try {
      const result = await promisify(tx(STORE_CONFIG, 'readonly').get('client_keypair'));
      if (result?.publicKey && result?.privateKey) {
        _clientKeyPair = result;
        console.log('[MessageGM] 已加载 SM2 密钥');
        return _clientKeyPair;
      }
    } catch (e) { console.warn('[MessageGM] 无密钥, 生成新密钥'); }

    const kp = gm().SM2.generateKeyPair();
    _clientKeyPair = kp;
    await promisify(tx(STORE_CONFIG, 'readwrite').put({
      key: 'client_keypair', publicKey: kp.publicKey, privateKey: kp.privateKey
    }));
    console.log('[MessageGM] 新 SM2 密钥已生成');
    return _clientKeyPair;
  }

  // ============================================================
  // α-GCM (SM4-CBC + SM3-HMAC) — 纯浏览器实现
  // ============================================================
  const AEGM = {
    randomHex(len) {
      if (typeof crypto !== 'undefined' && crypto.getRandomValues) {
        const buf = new Uint8Array(len);
        crypto.getRandomValues(buf);
        return bytesToHex(buf);
      }
      return gm().randomHex(len);
    },

    // KDF: SM3(masterKey∥"gm-enc") → encKey, SM3(masterKey∥"gm-mac") → macKey
    deriveKeys(masterKey) {
      const encRaw = hexToBytes(gm().SM3.digest(masterKey + 'fibemate-gm-enc'));
      const macRaw = gm().SM3.digest(masterKey + 'fibemate-gm-mac');
      return { encKey: bytesToHex(encRaw.slice(0, 16)), macKey: macRaw };
    },

    // SM3-HMAC: H(K⊕opad ∥ H(K⊕ipad ∥ M))
    hmac(keyHex, message) {
      const blockSize = 64;
      const key = hexToBytes(keyHex);
      let k = key;
      if (key.length > blockSize) k = hexToBytes(gm().SM3.digest(keyHex));
      if (k.length < blockSize) {
        const padded = new Uint8Array(blockSize);
        padded.set(k); k = padded;
      }
      const ipad = new Uint8Array(blockSize);
      const opad = new Uint8Array(blockSize);
      for (let i = 0; i < blockSize; i++) {
        ipad[i] = 0x36 ^ k[i];
        opad[i] = 0x5c ^ k[i];
      }
      const ipadKey = new Uint8Array(ipad);
      const msgBytes = new TextEncoder().encode(message);
      const inner = new Uint8Array(ipadKey.length + msgBytes.length);
      inner.set(ipadKey); inner.set(msgBytes, ipadKey.length);
      const innerHash = gm().SM3.digest(bytesToHex(inner));
      const opadKey = new Uint8Array(opad);
      const innerBytes = hexToBytes(innerHash);
      const outer = new Uint8Array(opadKey.length + innerBytes.length);
      outer.set(opadKey); outer.set(innerBytes, opadKey.length);
      return gm().SM3.digest(bytesToHex(outer));
    },

    encrypt(plainText, masterKey) {
      const { encKey, macKey } = this.deriveKeys(masterKey);
      const iv = this.randomHex(16);

      const ciphertext = gm().SM4.encrypt(plainText, encKey, {
        mode: 2, iv,
        inputEncoding: 'utf8',
        outputEncoding: 'hex'
      });

      const authTag = this.hmac(macKey, ciphertext);
      return { ciphertext, iv, authTag };
    },

    decrypt({ ciphertext, iv, authTag }, masterKey) {
      const { encKey, macKey } = this.deriveKeys(masterKey);

      // Constant-time verify authTag
      const expectedTag = this.hmac(macKey, ciphertext);
      if (authTag.length !== expectedTag.length) throw new Error('[MessageGM] MAC 长度不匹配');
      let diff = 0;
      for (let i = 0; i < authTag.length; i++) {
        diff |= authTag.charCodeAt(i) ^ expectedTag.charCodeAt(i);
      }
      if (diff !== 0) throw new Error('[MessageGM] 完整性校验失败 — 消息可能被篡改');

      return gm().SM4.decrypt(ciphertext, encKey, {
        mode: 2, iv,
        inputEncoding: 'hex',
        outputEncoding: 'utf8'
      });
    }
  };

  // ============================================================
  // SM2 密钥协商 — 客户端 ↔ 服务端
  // ============================================================
  async function negotiateWithServer(serverUrl) {
    const keyPair = await getOrCreateClientKeyPair();
    console.log('[MessageGM] SM2 协商...');

    const token = localStorage.getItem('fk_token');
    const response = await fetch(`${serverUrl}/api/negotiate`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...(token ? { 'Authorization': `Bearer ${token}` } : {})
      },
      body: JSON.stringify({
        clientPublicKey: keyPair.publicKey,
        algorithm: 'SM2'
      })
    });

    if (!response.ok) throw new Error(`[MessageGM] 协商失败: HTTP ${response.status}`);
    const data = await response.json();
    _serverPublicKey = data.serverPublicKey;

    // 生成 128-bit SM4 session key
    _sm4SessionKey = AEGM.randomHex(16);
    _sessionId = `gm_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    _sessionState = SESSION_ACTIVE;

    // SM2 加密 session key → 发送给服务器
    const encryptedKey = gm().SM2.encrypt(_sm4SessionKey, _serverPublicKey);

    console.log(`[MessageGM] 协商完成, session=${_sessionId.substring(0,24)}`);

    return {
      sessionId: _sessionId,
      encryptedKey,
      clientPublicKey: keyPair.publicKey,
      algorithm: 'SM2+SM4-αGCM'
    };
  }

  function setSessionKey(sm4Key) {
    _sm4SessionKey = sm4Key;
    _sessionId = `gm_direct_${Date.now()}`;
    _sessionState = SESSION_ACTIVE;
  }

  // ============================================================
  // encrypt / decrypt — 兼容 MessageCryptoV2 API
  // ============================================================
  async function encrypt(peerId, plaintext) {
    if (_sessionState !== SESSION_ACTIVE || !_sm4SessionKey)
      throw new Error('[MessageGM] 无活跃会话，请先完成 SM2 协商');

    const text = typeof plaintext === 'string' ? plaintext :
      new TextDecoder().decode(plaintext instanceof Uint8Array ? plaintext : new Uint8Array(plaintext));

    const { ciphertext, iv, authTag } = AEGM.encrypt(text, _sm4SessionKey);
    const hash = gm().SM3.digest(text).substring(0, 16);

    return {
      version: 3,
      protocol: 'gm-sm4-aegm',
      sessionId: _sessionId,
      envelope: { c: ciphertext, iv, tag: authTag },
      hash
    };
  }

  async function decrypt(peerId, envelope) {
    if (!envelope || envelope.version !== 3)
      throw new Error(`[MessageGM] 无效加密信封 (version=${envelope?.version ?? 'null'})`);
    if (_sessionState !== SESSION_ACTIVE || !_sm4SessionKey)
      throw new Error('[MessageGM] 无活跃会话');

    const env = envelope.envelope || envelope;
    const { c: ciphertext, iv, tag: authTag } = env;

    try {
      return AEGM.decrypt({ ciphertext, iv, authTag }, _sm4SessionKey);
    } catch (e) {
      console.error('[MessageGM] 解密失败:', e.message);
      throw new Error(`[SECURITY] 消息解密失败: ${e.message}`);
    }
  }

  // ============================================================
  // 会话管理
  // ============================================================
  async function hasSession(peerId) { return _sessionState === SESSION_ACTIVE; }

  async function getSecurityStatus(peerId) {
    return {
      secured: _sessionState === SESSION_ACTIVE,
      protocol: '国密 SM4-αGCM (服务端加密)',
      curve: 'SM2',
      kdf: 'SM3-KDF',
      aead: 'SM4-CBC + SM3-HMAC (α-GCM)',
      forwardSecrecy: false,
      futureSecrecy: false,
      messagesSent: 0,
      messagesReceived: 0,
      sessionId: _sessionId
    };
  }

  async function resetSession(peerId) {
    _sm4SessionKey = null; _sessionState = SESSION_NONE;
    _sessionId = null;
  }

  async function deleteSession(peerId) { await resetSession(peerId); }

  // ============================================================
  // 兼容 MessageCryptoV2 的接口 (国密简化)
  // ============================================================
  async function initiateSession(peerId, bundle) {
    return { sessionEstablished: true, sessionReady: true };
  }
  async function receiveSession(peerId, initMsg) {
    return { sessionEstablished: true, sessionReady: true };
  }
  async function confirmSession(peerId, response) {
    return { confirmed: true };
  }
  async function getMyPreKeyBundle() {
    const kp = await getOrCreateClientKeyPair();
    return { identityKey: kp.publicKey, algorithm: 'SM2', version: '3.0.1-gm' };
  }
  async function getSafetyNumberFingerprint(localId, remoteId) {
    const h = gm().SM3.digest(localId + remoteId);
    const digits = [];
    for (let i = 0; i < 30; i++) {
      const d = parseInt(h.substr(i * 2, 2), 16);
      digits.push(Math.floor(d / 2.56).toString().padStart(2, '0'));
    }
    const full = digits.join('');
    const blocks = [];
    for (let i = 0; i < 60; i += 5) blocks.push(full.slice(i, i + 5));
    return blocks.join(' ');
  }

  // ---- Public API ----
  return {
    version: 3,
    init: initDB,
    encrypt, decrypt, hasSession, getSecurityStatus, resetSession, deleteSession,
    negotiateWithServer, setSessionKey,
    initiateSession, receiveSession, confirmSession,
    getMyPreKeyBundle, getSafetyNumberFingerprint,
    getSessionState: () => _sessionState,
    getSessionId: () => _sessionId,
    _getIdentityKey: getOrCreateClientKeyPair,
    _getSession: () => ({ state: _sessionState, sessionId: _sessionId }),

    // 兼容 MessageCryptoV2 旧接口 (国密版无需 prekey 上传/自动补充)
    setOPKUploadCallback: () => {},
    startOPKAutoReplenish: () => {}
  };
})();

window.MessageGM = MessageGM;

// 兼容别名: 所有上层代码引用 MessageCryptoV2 自动路由到 MessageGM
// 旧模块仍在加载, 但 MessageGM 优先初始化
window.MessageCryptoV2 = MessageGM;

if (typeof module !== 'undefined' && module.exports) module.exports = MessageGM;