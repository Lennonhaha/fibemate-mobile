/**
 * FIBEMATE SM2 前端集成 API
 * ===========================
 * window.SM2 — SM2 七操作桥接层
 * 依赖: window.SM2EC (sm2-ec-browser.js v1.2, TVLA 5/5 PASS)
 * 设计: 同步 API, localStorage 密钥存储, 与 window.MLKEM768 风格对齐
 * 参考: GB/T 32918.2-4, SM2 椭圆曲线公钥密码算法
 *
 * v1.0 (2026-06-23)
 */

(function () {
  'use strict';

  if (!window.SM2EC) {
    console.error('[SM2] SM2EC not loaded. Ensure sm2-ec-browser.js is loaded before sm2-bridge.js.');
    return;
  }

  const SM2EC = window.SM2EC;
  const STORAGE_PREFIX = 'sm2_key_';
  const KEYS_LIST_KEY  = 'sm2_keys_list';

  // ========================
  // Key Storage (localStorage)
  // ========================

  function _keysList() {
    try {
      const raw = localStorage.getItem(KEYS_LIST_KEY);
      return raw ? JSON.parse(raw) : [];
    } catch { return []; }
  }

  function _saveKeysList(list) {
    localStorage.setItem(KEYS_LIST_KEY, JSON.stringify(list));
  }

  function _getKeyRecord(keyId) {
    try {
      const raw = localStorage.getItem(STORAGE_PREFIX + keyId);
      return raw ? JSON.parse(raw) : null;
    } catch { return null; }
  }

  function _saveKeyRecord(keyId, record) {
    localStorage.setItem(STORAGE_PREFIX + keyId, JSON.stringify(record));
  }

  function _deleteKeyRecord(keyId) {
    localStorage.removeItem(STORAGE_PREFIX + keyId);
  }

  // ========================
  // SM2 API
  // ========================

  const SM2 = {

    // ---------- 密钥生成 ----------

    /**
     * 生成 SM2 密钥对
     * @returns {{ keyId: string, publicKeyHex: string }}
     */
    generateKeyPair() {
      const kp = SM2EC.generateKeyPair();
      const publicKeyHex = SM2EC.publicKeyToHex(kp.publicKey);
      const privateKeyHex = SM2EC.bigIntToHex(kp.privateKey);

      // 保存到 localStorage
      const rec = {
        publicKeyHex: publicKeyHex,
        privateKeyHex: privateKeyHex,
        createdAt: Date.now()
      };

      // 使用递增数字作为 keyId
      const list = _keysList();
      const keyId = 'sm2-' + (list.length + 1);
      _saveKeyRecord(keyId, rec);

      list.push(keyId);
      _saveKeysList(list);

      console.log('[SM2] 密钥对已生成:', keyId, '公钥:', publicKeyHex.substring(0, 20) + '...');
      return { keyId: keyId, publicKeyHex: publicKeyHex };
    },

    // ---------- 公钥查询 ----------

    /**
     * 获取公钥
     * @param {string} keyId
     * @returns {{ publicKeyHex: string }}
     */
    getPublicKey(keyId) {
      const rec = _getKeyRecord(keyId);
      if (!rec) throw new Error('[SM2] Key not found: ' + keyId);
      return { publicKeyHex: rec.publicKeyHex };
    },

    /**
     * 导出公钥 (与 getPublicKey 同义, 保持 KeyStorage 命名一致)
     */
    exportPublicKey(keyId) {
      return this.getPublicKey(keyId);
    },

    // ---------- 签名与验签 ----------

    /**
     * SM2 签名 (GB/T 32918.2)
     * @param {string} keyId       密钥标识
     * @param {string} messageHex  SM3 哈希值 (hex)
     * @returns {{ r: string, s: string }}
     */
    sign(keyId, messageHex) {
      const rec = _getKeyRecord(keyId);
      if (!rec) throw new Error('[SM2] Key not found: ' + keyId);

      const privateKey = SM2EC.hexToBigInt(rec.privateKeyHex);
      return SM2EC.sign(privateKey, messageHex);
    },

    /**
     * SM2 验签
     * @param {string} publicKeyHex  公钥 (04 + 128 hex)
     * @param {string} messageHex    SM3 哈希值 (hex)
     * @param {string} r             签名的 r
     * @param {string} s             签名的 s
     * @returns {{ valid: boolean }}
     */
    verify(publicKeyHex, messageHex, r, s) {
      return { valid: SM2EC.verify(publicKeyHex, messageHex, r, s) };
    },

    // ---------- ECDH 密钥协商 ----------

    /**
     * SM2 ECDH 密钥协商
     * 返回共享密钥的 SM3 摘要 (32B = 64 hex)
     * @param {string} keyId         己方密钥标识
     * @param {string} peerPkHex     对方公钥 (04 + 128 hex)
     * @returns {{ ssId: string }}   共享密钥 hex (SM3 摘要)
     */
    ecdh(keyId, peerPkHex) {
      const rec = _getKeyRecord(keyId);
      if (!rec) throw new Error('[SM2] Key not found: ' + keyId);

      const privateKey = SM2EC.hexToBigInt(rec.privateKeyHex);
      const sharedBytes = SM2EC.computeSharedSecret(privateKey, peerPkHex);

      // SM3 摘要作为派生密钥 (与 KeyStorage.deriveSharedKey 对齐)
      let ssHex;
      if (window.SM3Hash && typeof window.SM3Hash.digestHex === 'function') {
        ssHex = window.SM3Hash.digestHex(sharedBytes);
      } else {
        // 回退: 直接 hex 编码前 32 字节
        ssHex = SM2EC.bytesToHex(sharedBytes).substring(0, 64);
      }
      return { ssId: ssHex };
    },

    // ---------- 加密与解密 ----------

    /**
     * SM2 加密 (GB/T 32918.4, C1C3C2 模式 — 简化版)
     * C1: 公钥加密的临时密文 (椭圆曲线点), C2: 密文
     * 注: C3 (SM3 摘要) 在此简化版中暂未分离, 内嵌于加密流程
     * @param {string} publicKeyHex  接收方公钥 (04 + 128 hex)
     * @param {string} plaintext     明文 (UTF-8)
     * @returns {{ c1Hex: string, c2Hex: string }}
     */
    encrypt(publicKeyHex, plaintext) {
      const result = SM2EC.encrypt(publicKeyHex, plaintext);
      return { c1Hex: result.c1, c2Hex: result.c2 };
    },

    /**
     * SM2 解密
     * @param {string} keyId         己方密钥标识
     * @param {string} c1Hex         C1 密文 (04 + 128 hex)
     * @param {string} c2Hex         C2 密文 (hex)
     * @returns {{ plaintext: string }}
     */
    decrypt(keyId, c1Hex, c2Hex) {
      const rec = _getKeyRecord(keyId);
      if (!rec) throw new Error('[SM2] Key not found: ' + keyId);

      const privateKey = SM2EC.hexToBigInt(rec.privateKeyHex);
      return { plaintext: SM2EC.decrypt(privateKey, c1Hex, c2Hex) };
    },

    // ---------- 密钥管理 ----------

    /**
     * 列出所有 SM2 密钥
     * @returns {Array<{ keyId: string, publicKeyHex: string, createdAt: number }>}
     */
    listKeys() {
      const list = _keysList();
      return list
        .map(id => {
          const rec = _getKeyRecord(id);
          if (!rec) return null;
          return {
            keyId: id,
            publicKeyHex: rec.publicKeyHex,
            createdAt: rec.createdAt
          };
        })
        .filter(Boolean);
    },

    /**
     * 检查密钥是否存在
     * @param {string} keyId
     * @returns {boolean}
     */
    hasKey(keyId) {
      return _getKeyRecord(keyId) !== null;
    },

    /**
     * 删除密钥
     * @param {string} keyId 
     */
    deleteKey(keyId) {
      _deleteKeyRecord(keyId);
      const list = _keysList().filter(id => id !== keyId);
      _saveKeysList(list);
      console.log('[SM2] 密钥已删除:', keyId);
    },

    /**
     * 清除所有 SM2 密钥
     */
    clearAllKeys() {
      const list = _keysList();
      list.forEach(id => _deleteKeyRecord(id));
      _saveKeysList([]);
      console.log('[SM2] 已清除全部 ' + list.length + ' 个密钥');
    },

    /**
     * 导入已有密钥 (用于系统初始化/恢复)
     * @param {string} keyId
     * @param {string} privateKeyHex
     */
    importKey(keyId, privateKeyHex) {
      const d = SM2EC.hexToBigInt(privateKeyHex);
      const pk = SM2EC.publicKeyFromPrivate(d);
      const rec = {
        publicKeyHex: SM2EC.publicKeyToHex(pk),
        privateKeyHex: privateKeyHex,
        createdAt: Date.now()
      };
      _saveKeyRecord(keyId, rec);

      const list = _keysList();
      if (!list.includes(keyId)) {
        list.push(keyId);
        _saveKeysList(list);
      }
      console.log('[SM2] 密钥已导入:', keyId);
      return { keyId, publicKeyHex: rec.publicKeyHex };
    },

    // ---------- 自检 ----------

    /**
     * SM2 全链路自检: 生成 → 签名/验签 → 加密/解密 → ECDH
     * @returns {{ ok: boolean, err?: string }}
     */
    selftest() {
      try {
        // 1. 生成密钥对
        const { publicKeyHex } = this.generateKeyPair();
        const keyId = _keysList()[_keysList().length - 1];

        // 2. 签名 + 验签
        const msg = new TextEncoder().encode('FIBEMATE SM2 selftest');
        let msgHash;
        if (window.SM3Hash && typeof window.SM3Hash.digestHex === 'function') {
          msgHash = window.SM3Hash.digestHex(msg);
        } else {
          msgHash = SM2EC.bytesToHex(msg);
        }
        const sig = this.sign(keyId, msgHash);
        const vrf = this.verify(publicKeyHex, msgHash, sig.r, sig.s);
        if (!vrf.valid) return { ok: false, err: 'sign/verify mismatch' };

        // 3. 加密 + 解密
        const enc = this.encrypt(publicKeyHex, 'hello SM2');
        const dec = this.decrypt(keyId, enc.c1Hex, enc.c2Hex);
        if (dec.plaintext !== 'hello SM2') return { ok: false, err: 'encrypt/decrypt mismatch' };

        // 4. ECDH
        const kp2 = SM2EC.generateKeyPair();
        const pk2 = SM2EC.publicKeyToHex(kp2.publicKey);
        this.importKey('sm2-selftest-peer', SM2EC.bigIntToHex(kp2.privateKey));
        const ss = this.ecdh(keyId, pk2);
        if (!ss.ssId || ss.ssId.length < 64) return { ok: false, err: 'ECDH failed' };

        // 5. 清理 selftest 密钥
        this.deleteKey(keyId);
        this.deleteKey('sm2-selftest-peer');

        return { ok: true };
      } catch (e) {
        return { ok: false, err: e.message };
      }
    }
  };

  // ========================
  // 导出
  // ========================
  window.SM2 = SM2;
  console.log('[SM2] SM2 前端集成 API 已就绪');

  // 启动时自动运行 selftest (延迟一帧，确保所有依赖就绪)
  if (typeof window !== 'undefined' && window.setTimeout) {
    setTimeout(() => {
      try {
        if (!window.SM2EC) { console.warn('[SM2] SM2EC not loaded, skipping selftest'); return; }
        if (!window.SM3Hash) { console.warn('[SM2] SM3Hash not loaded, skipping selftest'); return; }
        const result = SM2.selftest();
        console.log('[SM2] 自检:', result.ok ? '✅ PASS' : '❌ FAIL: ' + result.err);
      } catch (e) {
        console.warn('[SM2] 自检异常:', e.message, e.stack);
      }
    }, 100);
  }

})();
