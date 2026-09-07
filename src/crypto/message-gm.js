/**
 * FIBEMATE MessageGM — SM2-based Double Ratchet + SLH-DSA Signatures
 * ==================================================================
 * 国密版端到端加密：SM2 ECDH + SM3 KDF + SM4-GCM
 * 后量子签名 (v3): SLH-DSA-128s (FIPS 205)
 *
 * 协议栈: SM2 Key Exchange → Double Ratchet → SM4-GCM → SLH-DSA Sign
 * Curve: SM2 P-256 (GB/T 32918) | KDF: SM3-HMAC | AEAD: SM4-GCM
 *
 * 依赖: window.SM2EC, window.SM3Hash, window.SM4GCM
 * 可选: window.PQIntegration.SLHDSA (WASM, 签名增强)
 *
 * API (兼容 MessageCrypto): generateKeyPair, computeSharedSecret,
 *   encrypt, decrypt, hasSession, resetSession, getSecurityStatus
 */
const MessageGM = (() => {
  'use strict';

  // ================================================================
  //  Constants
  // ================================================================
  const DB_NAME = 'fibemate_gm';
  const STORE_SESSIONS = 'gm_sessions';
  const STORE_IDENTITY = 'gm_identity';
  const KEY_LEN = 32;       // SM3 output = 32 bytes → 64 hex chars
  const SM4_KEY_LEN = 32;   // SM4 key = 16 bytes → 32 hex chars
  const MAX_SKIP = 1000;

  let db = null;
  let _identityKeyPair = null;

  // ================================================================
  //  IndexedDB
  // ================================================================
  async function initDB() {
    return new Promise((resolve, reject) => {
      const request = indexedDB.open(DB_NAME, 1);
      request.onerror = () => reject(request.error);
      request.onsuccess = () => { db = request.result; resolve(db); };
      request.onupgradeneeded = (e) => {
        const database = e.target.result;
        if (!database.objectStoreNames.contains(STORE_SESSIONS))
          database.createObjectStore(STORE_SESSIONS, { keyPath: 'peerId' });
        if (!database.objectStoreNames.contains(STORE_IDENTITY))
          database.createObjectStore(STORE_IDENTITY, { keyPath: 'key' });
      };
    });
  }

  function tx(storeName, mode) {
    if (!db) throw new Error('[MessageGM] DB not initialized');
    return db.transaction(storeName, mode).objectStore(storeName);
  }

  function promisify(request) {
    return new Promise((resolve, reject) => {
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error);
    });
  }

  // ================================================================
  //  Crypto Helpers (all hex-based, synchronous or using window.*)
  // ================================================================
  const SM2 = window.SM2EC;
  const SM3 = window.SM3Hash;
  const SM4 = window.SM4GCM;

  function hexToBytes(hex) {
    const len = hex.length / 2;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++)
      bytes[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
    return bytes;
  }

  function bytesToHex(bytes) {
    return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
  }

  function strToBytes(s) { return new TextEncoder().encode(s); }
  function bytesToStr(b) { return new TextDecoder().decode(b); }

  /**
   * KDF_RK(rk: hex64, dh: hex64) → { rootKey: hex64, chainKey: hex64 }
   * HMAC-SM3 based root key ratchet
   */
  function kdfRk(rk, dh) {
    const ikm = rk + dh;
    // prk = HMAC-SM3(rk, dh)
    const prk = SM3.hmac(rk, ikm);
    // newRK = HMAC-SM3(prk, "FIBEMateRK" || 0x01)
    const newRK = SM3.hmac(prk, 'FIBEMateRK_01');
    // newCK = HMAC-SM3(prk, "FIBEMateCK" || 0x02)
    const newCK = SM3.hmac(prk, 'FIBEMateCK_02');
    return { rootKey: newRK, chainKey: newCK };
  }

  /**
   * KDF_CK(ck: hex64) → { messageKey: hex64, chainKey: hex64 }
   * HMAC-SM3 based chain key ratchet
   */
  function kdfCk(ck) {
    // mk = HMAC-SM3(ck, 0x01)
    const mk = SM3.hmac(ck, '\x01');
    // newCK = HMAC-SM3(ck, 0x02)
    const newCK = SM3.hmac(ck, '\x02');
    return { messageKey: mk, chainKey: newCK };
  }

  // ================================================================
  //  Identity Key Management
  // ================================================================
  async function getOrCreateIdentityKey() {
    if (_identityKeyPair) return _identityKeyPair;

    try {
      const result = await promisify(tx(STORE_IDENTITY, 'readonly').get('my_identity'));
      if (result?.publicKey && result?.privateKey) {
        _identityKeyPair = { publicKey: result.publicKey, privateKey: result.privateKey };
        console.log('[MessageGM] Loaded SM2 identity key from storage');
      }
    } catch (e) { /* not found, generate */ }

    if (!_identityKeyPair) {
      const raw = SM2.generateKeyPair();
      _identityKeyPair = {
        publicKey: SM2.publicKeyToHex(raw.publicKey),
        privateKey: SM2.bigIntToHex(raw.privateKey),
      };
      await promisify(tx(STORE_IDENTITY, 'readwrite').put({
        key: 'my_identity',
        publicKey: _identityKeyPair.publicKey,
        privateKey: _identityKeyPair.privateKey
      }));
      console.log('[MessageGM] Generated new SM2 identity key');
    }
    return _identityKeyPair;
  }

  // ================================================================
  //  SLH-DSA Signature Key Management (Phase 3 — FIPS 205)
  //  Prefers window.SLHDSA (clean ESM); falls back to PQIntegration.SLHDSA
  // ================================================================
  let _slhDsaKeyPair = null;
  let _slhDsaAvailable = null;  // null = unchecked, true/false

  function _getSlhProvider() {
    return window.SLHDSA || window.PQIntegration?.SLHDSA || null;
  }

  async function _checkSlhDsa() {
    if (_slhDsaAvailable === true) return true;
    try {
      const provider = _getSlhProvider();
      if (!provider) {
        _slhDsaAvailable = false;
        return false;
      }
      _slhDsaAvailable = await provider.isAvailable();
      console.log('[MessageGM] SLH-DSA available:', _slhDsaAvailable);
    } catch (e) {
      console.warn('[MessageGM] SLH-DSA check failed:', e.message);
      _slhDsaAvailable = null;  // Don't cache failure — retry on next call
      return false;
    }
    return _slhDsaAvailable;
  }

  async function _getOrCreateSlhDsaKey() {
    if (_slhDsaKeyPair) return _slhDsaKeyPair;

    const available = await _checkSlhDsa();
    if (!available) return null;

    try {
      const result = await promisify(tx(STORE_IDENTITY, 'readonly').get('slh_dsa_identity'));
      if (result?.publicKey && result?.secretKey) {
        _slhDsaKeyPair = { publicKey: result.publicKey, secretKey: result.secretKey };
        console.log('[MessageGM] Loaded SLH-DSA identity key from storage');
      }
    } catch (e) { /* not found */ }

    if (!_slhDsaKeyPair) {
      const provider = _getSlhProvider();
      const keys = await provider.keygen();
      _slhDsaKeyPair = { publicKey: keys.publicKey, secretKey: keys.secretKey };
      await promisify(tx(STORE_IDENTITY, 'readwrite').put({
        key: 'slh_dsa_identity',
        publicKey: _slhDsaKeyPair.publicKey,
        secretKey: _slhDsaKeyPair.secretKey
      }));
      console.log('[MessageGM] Generated new SLH-DSA identity key');
    }
    return _slhDsaKeyPair;
  }

  // ================================================================
  //  DR State Factory
  // ================================================================
  function createState() {
    return {
      rootKey: null,           // hex64 (SM3 output)
      sendingChainKey: null,   // hex64 or null
      receivingChainKey: null, // hex64 or null
      selfDHPub: null,         // hex130 (SM2 public key 04||x||y)
      selfDHPriv: null,        // hex64 (SM2 private key scalar)
      remoteDHPub: null,       // hex130
      sendMessageNumber: 0,
      recvMessageNumber: 0,
      prevSendChainLength: 0,
      skippedKeys: new Map(),  // key: "dhPub:n" → { mk: hex64 }
      _createdAt: Date.now()
    };
  }

  // ================================================================
  //  Ratchet Header
  // ================================================================
  function makeHeader(selfDHPub, pn, n) {
    return { dh: selfDHPub, pn, n };
  }

  function headerAAD(header) {
    // Deterministic AAD: "dh|pn|n"
    return header.dh + '|' + header.pn + '|' + header.n;
  }

  // ================================================================
  //  Skipped Key Management
  // ================================================================
  function skipMessageKeys(state, until) {
    if (state.recvMessageNumber + MAX_SKIP < until) {
      throw new Error(`[MessageGM] Too many skipped messages: ${until - state.recvMessageNumber}`);
    }
    if (!state.receivingChainKey) return;

    while (state.recvMessageNumber < until) {
      const { messageKey, chainKey } = kdfCk(state.receivingChainKey);
      const key = state.remoteDHPub + ':' + state.recvMessageNumber;
      state.skippedKeys.set(key, { mk: messageKey });
      state.receivingChainKey = chainKey;
      state.recvMessageNumber++;
    }
  }

  function trySkippedKeys(state, header, ct, iv, aad) {
    const key = header.dh + ':' + header.n;
    const entry = state.skippedKeys.get(key);
    if (!entry) return null;
    state.skippedKeys.delete(key);
    try {
      // SM4-GCM decrypt with mk
      const mkSm4 = entry.mk.substring(0, SM4_KEY_LEN);
      const pt = SM4.decrypt(ct, mkSm4, iv, /*authTag in ct?*/ '');
      // SM4GCM.decrypt expects (cipherHex, keyHex, ivHex, authTagHex)
      // But we need to re-derive: the encrypt() produces {ciphertext, iv, authTag}
      // We stored mk but not authTag. The trySkipped pattern is to try decryption.
      // Need to restructure — skip entries should store mk only.
      // Actually we need the full decrypt to work.
      return null; // This won't work without auth tag. See redesign below.
    } catch (e) {
      return null;
    }
  }

  /**
   * Encrypt AEAD: SM4-GCM with ratchet header as AAD
   * Returns { ciphertext: hex, iv: hex, authTag: hex, header }
   */
  function encryptMessage(state) {
    if (!state.sendingChainKey) {
      throw new Error('[MessageGM] No sending chain — DH ratchet not yet established');
    }

    const { messageKey, chainKey } = kdfCk(state.sendingChainKey);
    state.sendingChainKey = chainKey;

    const header = makeHeader(state.selfDHPub, state.prevSendChainLength, state.sendMessageNumber);
    const aad = headerAAD(header);
    const mkSm4 = messageKey.substring(0, SM4_KEY_LEN);

    const enc = SM4.encrypt('__PLACEHOLDER__', mkSm4, { aad });
    // SM4GCM.encrypt generates random IV internally
    // We need to pass the plaintext later, this is just setup

    state.sendMessageNumber++;
    return { header, mkSm4, aad };
  }

  // ================================================================
  //  DH Ratchet Step
  // ================================================================
  function performDHRatchet(state, header) {
    const prevChainLen = state.sendMessageNumber;

    // Skip message keys on receiving chain
    skipMessageKeys(state, header.pn);

    // Receive-side DH ratchet
    state.remoteDHPub = header.dh;
    const dh1 = computeSharedSecret(state.selfDHPriv, state.remoteDHPub);
    const rkck1 = kdfRk(state.rootKey, dh1);
    state.rootKey = rkck1.rootKey;
    state.receivingChainKey = rkck1.chainKey;
    state.recvMessageNumber = 0;
    state.prevSendChainLength = prevChainLen;

    // Generate new self DH key
    const rawDH = SM2.generateKeyPair();
    state.selfDHPub = SM2.publicKeyToHex(rawDH.publicKey);
    state.selfDHPriv = SM2.bigIntToHex(rawDH.privateKey);

    // Send-side DH ratchet
    const dh2 = computeSharedSecret(state.selfDHPriv, state.remoteDHPub);
    const rkck2 = kdfRk(state.rootKey, dh2);
    state.rootKey = rkck2.rootKey;
    state.sendingChainKey = rkck2.chainKey;
    state.sendMessageNumber = 0;
  }

  // ================================================================
  //  DR Encrypt
  // ================================================================
  function drEncrypt(state, plaintext) {
    if (!state.sendingChainKey) {
      throw new Error('[MessageGM] No sending chain');
    }

    const { messageKey, chainKey } = kdfCk(state.sendingChainKey);
    state.sendingChainKey = chainKey;

    const header = makeHeader(state.selfDHPub, state.prevSendChainLength, state.sendMessageNumber);
    const aad = headerAAD(header);
    const mkSm4 = messageKey.substring(0, SM4_KEY_LEN);

    const enc = SM4.encrypt(plaintext, mkSm4, { aad });
    state.sendMessageNumber++;

    return {
      header,
      ciphertext: enc.ciphertext,
      iv: enc.iv,
      authTag: enc.authTag,
    };
  }

  /**
   * DR Decrypt
   */
  function drDecrypt(state, header, ciphertext, iv, authTag) {
    // 1. Try skipped keys
    const skipKey = header.dh + ':' + header.n;
    const skippedEntry = state.skippedKeys.get(skipKey);
    if (skippedEntry) {
      state.skippedKeys.delete(skipKey);
      const mkSm4 = skippedEntry.mk.substring(0, SM4_KEY_LEN);
      const aad = headerAAD(header);
      const pt = SM4.decrypt(ciphertext, mkSm4, iv, authTag, aad);
      if (pt !== null) return pt;
      throw new Error('[MessageGM] Decryption failed with skipped key — possible replay attack');
    }

    // 2. DH ratchet if remote key changed
    if (header.dh !== state.remoteDHPub) {
      performDHRatchet(state, header);
    }

    // 3. Ensure receiving chain exists
    if (!state.receivingChainKey) {
      throw new Error('[MessageGM] No receiving chain');
    }

    // 4. Skip to target message number
    skipMessageKeys(state, header.n);

    // 5. Derive message key
    if (!state.receivingChainKey) {
      throw new Error('[MessageGM] No receiving chain');
    }

    const { messageKey, chainKey } = kdfCk(state.receivingChainKey);
    state.receivingChainKey = chainKey;
    state.recvMessageNumber++;

    // 5. Decrypt
    const aad = headerAAD(header);
    const mkSm4 = messageKey.substring(0, SM4_KEY_LEN);
    const pt = SM4.decrypt(ciphertext, mkSm4, iv, authTag, aad);

    if (pt === null) {
      throw new Error(
        '[SECURITY ALERT] SM4-GCM authentication failed.\n' +
        'Message may have been tampered with or session is desynchronized.'
      );
    }
    return pt;
  }

  // ================================================================
  //  Session Persistence
  // ================================================================
  const sessionCache = new Map();

  async function loadSession(peerId) {
    try {
      const result = await promisify(tx(STORE_SESSIONS, 'readonly').get(peerId));
      if (!result?.state) return null;
      return importState(result.state);
    } catch (e) {
      return null;
    }
  }

  async function saveSession(peerId, state) {
    const exported = exportState(state);
    await promisify(tx(STORE_SESSIONS, 'readwrite').put({ peerId, state: exported }));
  }

  async function getSession(peerId) {
    if (sessionCache.has(peerId)) return sessionCache.get(peerId);
    const state = await loadSession(peerId);
    if (state) sessionCache.set(peerId, state);
    return state;
  }

  async function updateSession(peerId, state) {
    sessionCache.set(peerId, state);
    await saveSession(peerId, state);
  }

  async function deleteSession(peerId) {
    sessionCache.delete(peerId);
    try {
      await promisify(tx(STORE_SESSIONS, 'readwrite').delete(peerId));
    } catch (e) { /* ok */ }
  }

  function exportState(state) {
    return {
      rootKey: state.rootKey,
      sendingChainKey: state.sendingChainKey,
      receivingChainKey: state.receivingChainKey,
      selfDHPub: state.selfDHPub,
      selfDHPriv: state.selfDHPriv,
      remoteDHPub: state.remoteDHPub,
      sendMessageNumber: state.sendMessageNumber,
      recvMessageNumber: state.recvMessageNumber,
      prevSendChainLength: state.prevSendChainLength,
      skippedKeys: Array.from(state.skippedKeys.entries()),
      _createdAt: state._createdAt
    };
  }

  function importState(data) {
    const state = createState();
    state.rootKey = data.rootKey;
    state.sendingChainKey = data.sendingChainKey;
    state.receivingChainKey = data.receivingChainKey;
    state.selfDHPub = data.selfDHPub;
    state.selfDHPriv = data.selfDHPriv;
    state.remoteDHPub = data.remoteDHPub;
    state.sendMessageNumber = data.sendMessageNumber || 0;
    state.recvMessageNumber = data.recvMessageNumber || 0;
    state.prevSendChainLength = data.prevSendChainLength || 0;
    state.skippedKeys = new Map(data.skippedKeys || []);
    state._createdAt = data._createdAt || Date.now();
    return state;
  }

  // ================================================================
  //  Key Exchange: SM2 ECDH (simplified, replaces X3DH 4-DH)
  // ================================================================
  // Alice → Bob flow:
  //   1. Alice: generate ephemeral SM2 key pair (EK_A)
  //   2. Alice: DH1 = computeSharedSecret(IK_A, IK_B), DH2 = computeSharedSecret(EK_A, IK_B)
  //   3. Alice: rootKey = KDF(DH1 || DH2, 64)
  //   4. Alice sends EK_A.pub to Bob → initializes DR
  //   5. Bob: same DH → same rootKey → initializes DR as receiver

  /**
   * Alice initiates session with Bob
   * @param {string} peerId - Bob's user ID
   * @param {string} bobPublicKey - Bob's SM2 identity public key (hex130)
   */
  async function initiateSession(peerId, bobPublicKey) {
    const identity = await getOrCreateIdentityKey();

    // Generate ephemeral key
    const rawEK = SM2.generateKeyPair();
    const ek = {
      publicKey: SM2.publicKeyToHex(rawEK.publicKey),
      privateKey: SM2.bigIntToHex(rawEK.privateKey),
    };

    // DH1: IK_A × IK_B
    const dh1 = computeSharedSecret(identity.privateKey, bobPublicKey);

    // DH2: EK_A × IK_B
    const dh2 = computeSharedSecret(ek.privateKey, bobPublicKey);

    // Derive root key
    const combined = dh1 + dh2;
    const rootKey = SM3.hmac('SM2_X3DH_ROOT_KEY__', combined);

    // Initialize DR as initiator (Bob's IK as initial remote DH key)
    const state = createState();
    state.rootKey = rootKey;
    state.remoteDHPub = bobPublicKey;
    state.selfDHPub = ek.publicKey;
    state.selfDHPriv = ek.privateKey;

    // DH ratchet: self DH × remote IK → derive sending chain
    const dh = computeSharedSecret(ek.privateKey, bobPublicKey);
    const rkck = kdfRk(rootKey, dh);
    state.rootKey = rkck.rootKey;
    state.sendingChainKey = rkck.chainKey;
    state.receivingChainKey = null;
    state.sendMessageNumber = 0;
    state.recvMessageNumber = 0;
    state.prevSendChainLength = 0;

    await updateSession(peerId, state);

    console.log(`[MessageGM] Session initiated with ${peerId}`);

    return {
      initialMessage: {
        type: 'gm_key_exchange',
        identityKey: identity.publicKey,
        ephemeralKey: ek.publicKey,
      },
      sessionEstablished: true,
    };
  }

  /**
   * Bob receives Alice's session initiation
   * @param {string} peerId - Alice's user ID
   * @param {object} aliceInit - { identityKey, ephemeralKey }
   */
  async function receiveSession(peerId, aliceInit) {
    const identity = await getOrCreateIdentityKey();
    const aliceIK = aliceInit.identityKey;
    const aliceEK = aliceInit.ephemeralKey;

    // DH1: IK_B × IK_A
    const dh1 = computeSharedSecret(identity.privateKey, aliceIK);

    // DH2: IK_B × EK_A
    const dh2 = computeSharedSecret(identity.privateKey, aliceEK);

    // Derive root key (must match Alice's)
    const combined = dh1 + dh2;
    const rootKey = SM3.hmac('SM2_X3DH_ROOT_KEY__', combined);

    // Initialize DR as receiver — do full DH ratchet
    const state = createState();
    state.remoteDHPub = aliceEK;

    // Generate Bob's own ephemeral DH key for ratchet
    const rawBobEK = SM2.generateKeyPair();
    const bobEK = {
      publicKey: SM2.publicKeyToHex(rawBobEK.publicKey),
      privateKey: SM2.bigIntToHex(rawBobEK.privateKey),
    };

    // Receive-side DH ratchet: IK_B × EK_A → receiving chain
    const rdh = computeSharedSecret(identity.privateKey, aliceEK);
    const rkck1 = kdfRk(rootKey, rdh);
    state.rootKey = rkck1.rootKey;
    state.receivingChainKey = rkck1.chainKey;
    state.recvMessageNumber = 0;

    // Send-side DH ratchet: EK_B × EK_A → sending chain
    const sdh = computeSharedSecret(bobEK.privateKey, aliceEK);
    const rkck2 = kdfRk(state.rootKey, sdh);
    state.rootKey = rkck2.rootKey;
    state.sendingChainKey = rkck2.chainKey;
    state.sendMessageNumber = 0;

    state.selfDHPub = bobEK.publicKey;
    state.selfDHPriv = bobEK.privateKey;
    state.prevSendChainLength = 0;

    await updateSession(peerId, state);

    console.log(`[MessageGM] Session received from ${peerId}`);

    return {
      responseMessage: {
        type: 'gm_key_accept',
        identityKey: identity.publicKey,
        accepted: true,
      },
      sessionEstablished: true,
      sessionReady: true,
    };
  }

  // ================================================================
  //  Public API
  // ================================================================

  /**
   * Encrypt message for peer with optional SLH-DSA signing (Phase 3).
   * @param {string} peerId
   * @param {string} plaintext
   * @returns {Promise<object>} opaque envelope
   */
  async function encrypt(peerId, plaintext) {
    const state = await getSession(peerId);
    if (!state) {
      throw new Error(
        `[MessageGM] No secure session with "${peerId}". ` +
        `Complete SM2 key exchange first.`
      );
    }

    const result = drEncrypt(state, plaintext);
    await updateSession(peerId, state);

    /** @type {object} */
    const envelope = {
      version: 2,
      protocol: 'double-ratchet-sm',
      envelope: {
        h: result.header,
        c: result.ciphertext,
        iv: result.iv,
        t: result.authTag,
      },
    };

    // Phase 3: Attach SLH-DSA signature (FIPS 205)
    // Signature covers the entire envelope object to detect any tampering.
    // Public key is embedded in the sig block so the receiver can verify
    // without an out-of-band key exchange.
    try {
      const slhKey = await _getOrCreateSlhDsaKey();
      if (slhKey) {
        const signPayload = JSON.stringify(envelope.envelope);
        const provider = _getSlhProvider();
        const sigValue = await provider.sign(
          signPayload, slhKey.secretKey, slhKey.publicKey
        );
        envelope.sig = {
          algorithm: 'slh-dsa-128s',
          value: sigValue,
          publicKey: slhKey.publicKey,
        };
        console.log('[MessageGM] SLH-DSA signature attached (%d chars)', sigValue.length);
      }
    } catch (e) {
      // Degrade gracefully — message is still encrypted, just unsigned
      console.warn('[MessageGM] SLH-DSA signing skipped:', e.message);
    }

    return envelope;
  }

  /**
   * Decrypt message from peer with optional SLH-DSA verification (Phase 3).
   */
  async function decrypt(peerId, envelope) {
    if (!envelope || envelope.version !== 2) {
      throw new Error(
        `[MessageGM] Invalid envelope version=${envelope?.version ?? 'null'}.`
      );
    }

    // Phase 3: Verify SLH-DSA signature if present
    // Verifies envelope integrity before attempting decryption.
    if (envelope.sig) {
      try {
        const available = await _checkSlhDsa();
        if (available) {
          const signPayload = JSON.stringify(envelope.envelope);
          const provider = _getSlhProvider();
          const valid = await provider.verify(
            envelope.sig.value, signPayload, envelope.sig.publicKey
          );
          if (!valid) {
            throw new Error(
              '[SECURITY ALERT] SLH-DSA signature verification FAILED.\n' +
              '  Message may have been tampered with in transit.\n' +
              `  Peer: ${peerId}\n` +
              `  Algorithm: ${envelope.sig.algorithm || 'unknown'}`
            );
          }
          console.log('[MessageGM] SLH-DSA signature verified ✓');
        }
      } catch (e) {
        if (e.message.includes('SLH-DSA signature verification FAILED')) {
          throw e;  // Re-throw security alert
        }
        console.warn('[MessageGM] SLH-DSA verification skipped:', e.message);
      }
    }

    const state = await getSession(peerId);
    if (!state) {
      throw new Error(
        `[MessageGM] Cannot decrypt from "${peerId}": no session.`
      );
    }

    const { h: header, c: ciphertext, iv, t: authTag } = envelope.envelope;

    try {
      const plaintext = drDecrypt(state, header, ciphertext, iv, authTag);
      await updateSession(peerId, state);
      return plaintext;
    } catch (e) {
      console.error(`[MessageGM] Decrypt failed for ${peerId}:`, e.message);
      throw new Error(
        `[SECURITY ALERT] Decrypt failed: ${e.message}\n` +
        `Peer: ${peerId}\n` +
        `Check Safety Numbers or re-establish session.`
      );
    }
  }

  // ================================================================
  //  SM2 Direct Encryption (Sessionless — ECIES Hybrid)
  // ================================================================
  //
  // For messages where no Double Ratchet session exists (first-contact,
  // one-off encrypted messages, offline recipients). Uses SM2 public-key
  // encryption to wrap a random SM4 session key; then SM4-GCM encrypts
  // the message body.
  //
  // Envelope v3: { version:3, protocol:'sm2-sm4-hybrid',
  //                 sm2:{c1,c2}, sm4:{ciphertext,iv,authTag} }

  /**
   * Encrypt message directly with recipient's SM2 public key.
   * No Double Ratchet session required.
   *
   * Hybrid scheme:
   *   1. Generate random 16-byte SM4 session key
   *   2. SM2-encrypt the SM4 key with recipient's public key
   *   3. SM4-GCM encrypt the plaintext with the SM4 key
   *
   * @param {string} plaintext           - Message to encrypt (UTF-8)
   * @param {string} recipientPublicKeyHex - Recipient's SM2 public key (04+128 hex, 130 chars)
   * @returns {{ version:3, protocol:'sm2-sm4-hybrid',
   *             sm2:{c1,c2}, sm4:{ciphertext,iv,authTag} }}
   */
  function encryptWithSM2(plaintext, recipientPublicKeyHex) {
    // Validate public key
    if (!recipientPublicKeyHex
        || !recipientPublicKeyHex.startsWith('04')
        || recipientPublicKeyHex.length !== 130) {
      throw new Error(
        `[MessageGM] Invalid SM2 public key: ` +
        `expected 04+128 hex (len=130), got len=${recipientPublicKeyHex?.length ?? 0}`
      );
    }

    // 1. Random SM4 session key (16 bytes → 32 hex chars)
    const sm4KeyBytes = new Uint8Array(16);
    crypto.getRandomValues(sm4KeyBytes);
    const sm4KeyHex = bytesToHex(sm4KeyBytes);

    // 2. SM2-encrypt the SM4 session key
    const sm2Enc = SM2.encrypt(recipientPublicKeyHex, sm4KeyHex);

    // 3. SM4-GCM encrypt the message
    // AAD = first 32 hex chars of SM2 c1 (ephemeral public point)
    // Binds SM4 ciphertext to this specific SM2 envelope; decrypt side
    // can independently compute the same AAD from c1 in the envelope.
    const aad = sm2Enc.c1.substring(0, 32);
    const sm4Enc = SM4.encrypt(plaintext, sm4KeyHex, { aad });

    console.log('[MessageGM] SM2-SM4 encrypted (%d plain bytes, key=%s…)',
      new TextEncoder().encode(plaintext).length, sm4KeyHex.substring(0, 8));

    return {
      version: 3,
      protocol: 'sm2-sm4-hybrid',
      sm2: { c1: sm2Enc.c1, c2: sm2Enc.c2 },
      sm4: { ciphertext: sm4Enc.ciphertext, iv: sm4Enc.iv, authTag: sm4Enc.authTag },
    };
  }

  /**
   * Decrypt message encrypted with encryptWithSM2().
   * Uses the receiver's SM2 identity key (stored in IndexedDB).
   *
   * @param {object} envelope - { version, protocol, sm2:{c1,c2}, sm4:{ciphertext,iv,authTag} }
   * @returns {Promise<string>} plaintext
   */
  async function decryptWithSM2(envelope) {
    if (!envelope || envelope.version !== 3
        || envelope.protocol !== 'sm2-sm4-hybrid') {
      throw new Error(
        `[MessageGM] Invalid sm2-sm4-hybrid envelope: ` +
        `version=${envelope?.version}, protocol=${envelope?.protocol}`
      );
    }

    const { sm2: sm2Env, sm4: sm4Env } = envelope;
    if (!sm2Env?.c1 || !sm2Env?.c2
        || !sm4Env?.ciphertext || !sm4Env?.iv || !sm4Env?.authTag) {
      throw new Error('[MessageGM] Incomplete sm2-sm4-hybrid envelope');
    }

    // 1. SM2-decrypt → SM4 session key
    const identity = await getOrCreateIdentityKey();
    const privateKeyBigInt = SM2.hexToBigInt(identity.privateKey);
    const sm4KeyHex = SM2.decrypt(privateKeyBigInt, sm2Env.c1, sm2Env.c2);

    // 2. SM4-GCM decrypt
    // AAD = first 32 hex chars of SM2 c1 (from envelope) — matches encrypt side
    const aad = sm2Env.c1.substring(0, 32);
    const plaintext = SM4.decrypt(
      sm4Env.ciphertext, sm4KeyHex, sm4Env.iv, sm4Env.authTag, aad
    );

    if (plaintext === null) {
      throw new Error(
        '[SECURITY ALERT] SM2-SM4 decryption FAILED.\n' +
        '  Ciphertext may have been tampered with or wrong key used.\n' +
        '  SM4-GCM authentication tag did not verify.'
      );
    }

    console.log('[MessageGM] SM2-SM4 decrypted (%d plain bytes)',
      new TextEncoder().encode(plaintext).length);
    return plaintext;
  }

  /**
   * Check if session exists for peer
   */
  async function hasSession(peerId) {
    const state = await getSession(peerId);
    return state !== null;
  }

  /**
   * Reset session (full forward secrecy break)
   */
  async function resetSession(peerId) {
    sessionCache.delete(peerId);
    await deleteSession(peerId);
    console.log(`[MessageGM] Session reset for ${peerId}`);
  }

  /**
   * Get security status for UI.
   * Now includes post-quantum signature status (Phase 3).
   */
  async function getSecurityStatus(peerId) {
    const state = await getSession(peerId);
    if (!state) {
      return { secured: false, protocol: null, forwardSecrecy: false };
    }

    const slhAvailable = await _checkSlhDsa();

    return {
      secured: true,
      protocol: 'Double Ratchet (SM2/SM3/SM4)',
      curve: 'SM2 P-256 (GB/T 32918)',
      kdf: 'SM3-HMAC (GB/T 32905)',
      aead: 'SM4-GCM (GB/T 32907)',
      signatureAlgorithm: slhAvailable ? 'SLH-DSA-128s (FIPS 205)' : null,
      postQuantumSignature: slhAvailable,
      forwardSecrecy: true,
      futureSecrecy: true,
      messagesSent: state.sendMessageNumber,
      messagesReceived: state.recvMessageNumber,
      skippedKeysCount: state.skippedKeys.size,
      sessionAge: Date.now() - (state._createdAt || Date.now()),
    };
  }

  /**
   * Reset identity key cache (for testing / key rotation).
   * Next call to getOrCreateIdentityKey will reload from IndexedDB
   * or generate a new one.
   */
  async function resetIdentityCache() {
    _identityKeyPair = null;
  }

  /**
   * Get my SM2 identity public key (hex130)
   */
  async function getMyPublicKey() {
    const identity = await getOrCreateIdentityKey();
    return identity.publicKey;
  }

  /**
   * Get my SLH-DSA identity public key (base64, ~44 chars).
   * Returns null if WASM module not available.
   * @returns {Promise<string|null>}
   */
  async function getSlhDsaPublicKey() {
    const key = await _getOrCreateSlhDsaKey();
    return key?.publicKey ?? null;
  }

  /**
   * Check if SLH-DSA post-quantum signatures are available.
   * @returns {Promise<boolean>}
   */
  async function isSlhDsaAvailable() {
    return _checkSlhDsa();
  }

  /**
   * Static: generate a new SM2 key pair
   */
  function generateKeyPair() {
    const kp = SM2.generateKeyPair();
    return {
      publicKey: SM2.publicKeyToHex(kp.publicKey),
      privateKey: SM2.bigIntToHex(kp.privateKey),
    };
  }

  /**
   * Static: compute ECDH shared secret (returns hex64)
   */
  function computeSharedSecret(privateKeyHex, publicKeyHex) {
    const result = SM2.computeSharedSecret(privateKeyHex, publicKeyHex);
    // SM2 ECDH returns x||y (64 bytes); we use only x (first 32 bytes) per GB/T 32918.3
    const xOnly = result.slice(0, 32);
    return bytesToHex(xOnly);
  }

  /**
   * Generate Safety Number fingerprint (SM3-based, 60 digits)
   */
  async function getSafetyNumberFingerprint(localUserId, remoteUserId, remotePublicKey) {
    const identity = await getOrCreateIdentityKey();
    const localPub = identity.publicKey;

    const ids = [localUserId, remoteUserId].sort();
    const id1 = strToBytes(ids[0]);
    const id2 = strToBytes(ids[1]);
    const key1 = ids[0] === localUserId
      ? hexToBytes(localPub)
      : hexToBytes(remotePublicKey);
    const key2 = ids[0] === localUserId
      ? hexToBytes(remotePublicKey)
      : hexToBytes(localPub);

    const combined = new Uint8Array(id1.length + key1.length + id2.length + key2.length);
    combined.set(id1, 0);
    combined.set(key1, id1.length);
    combined.set(id2, id1.length + key1.length);
    combined.set(key2, id1.length + key1.length + id2.length);

    // SM3 hash → hex → take first 30 bytes → 60 digits
    const hashHex = SM3.digestHex(combined);
    const hash = hexToBytes(hashHex);
    const digits = [];
    for (let i = 0; i < 30; i++) {
      digits.push(Math.floor(hash[i] / 2.56).toString().padStart(2, '0'));
    }
    const full = digits.join('');
    const blocks = [];
    for (let i = 0; i < 60; i += 5) {
      blocks.push(full.slice(i, i + 5));
    }
    return blocks.join(' ');
  }

  // ================================================================
  //  Module Export
  // ================================================================
  return {
    version: 3,  // bumped: SLH-DSA signature support

    // Init
    init: initDB,

    // Identity
    getMyPublicKey,
    resetIdentityCache,
    getSlhDsaPublicKey,
    isSlhDsaAvailable,
    generateKeyPair,
    computeSharedSecret,

    // Key Exchange
    initiateSession,
    receiveSession,

    // Core Encryption (Double Ratchet — session)
    encrypt,
    decrypt,

    // SM2 Direct Encryption (sessionless — first contact / one-off)
    encryptWithSM2,
    decryptWithSM2,

    hasSession,

    // Session Management
    resetSession,
    getSecurityStatus,
    deleteSession,

    // Safety Numbers
    getSafetyNumberFingerprint,

    // Internal (testing)
    _getIdentityKey: getOrCreateIdentityKey,
    _getSlhDsaKey: _getOrCreateSlhDsaKey,
    _getSession: getSession,
    _drEncrypt: drEncrypt,
    _drDecrypt: drDecrypt,
    _kdfRk: kdfRk,
    _kdfCk: kdfCk,
  };
})();

// Exports
if (typeof window !== 'undefined') window.MessageGM = MessageGM;
if (typeof module !== 'undefined' && module.exports) module.exports = MessageGM;
