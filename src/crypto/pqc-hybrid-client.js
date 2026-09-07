/**
 * pqc-hybrid-client.js — 路径 C-2: 浏览器端 SM2+ML-KEM-768 混合密钥交换
 * 
 * 依赖：
 *   - ML-KEM-768 (window.MLKEM768 或动态加载)
 *   - SM2EC (window.SM2EC, sm2-ec-browser.js v1.2)
 *   - Web Crypto API (HKDF-SHA256)
 * 
 * IANA #4590 应用层落地实现
 */
const PqcHybridClient = (() => {
  let _ready = false;

  // Resolve ML-KEM-768
  async function _getMlkem() {
    if (window.MLKEM768 && typeof window.MLKEM768.encapsulate === 'function') {
      return window.MLKEM768;
    }
    if (typeof MLKEM768 !== 'undefined') return MLKEM768;
    throw new Error('ML-KEM-768 not loaded');
  }

  // Resolve SM2
  function _getSm2() {
    if (window.SM2EC && typeof window.SM2EC.generateKeyPair === 'function') {
      return window.SM2EC;
    }
    throw new Error('SM2EC not loaded — include sm2-ec-browser.js first');
  }

  // HKDF via Web Crypto
  async function _hkdfExtract(salt, ikm) {
    const key = await crypto.subtle.importKey('raw', ikm, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    const sig = await crypto.subtle.sign('HMAC', key, salt);
    return new Uint8Array(sig);
  }

  async function _hkdfExpand(prk, info, length) {
    const hmacAlgo = { name: 'HMAC', hash: 'SHA-256' };
    const hmacKey = await crypto.subtle.importKey('raw', prk, hmacAlgo, false, ['sign']);
    const n = Math.ceil(length / 32);
    const blocks = [];
    let prev = new Uint8Array(0);
    for (let i = 0; i < n; i++) {
      const data = new Uint8Array([...prev, ...info, i + 1]);
      prev = new Uint8Array(await crypto.subtle.sign('HMAC', hmacKey, data));
      blocks.push(prev);
    }
    const out = new Uint8Array(n * 32);
    for (let i = 0; i < n; i++) out.set(blocks[i], i * 32);
    return out.slice(0, length);
  }

  // hex <-> Uint8Array
  function hexToBytes(h) { return new Uint8Array(h.match(/.{1,2}/g).map(b => parseInt(b, 16))); }
  function bytesToHex(b) { return [...b].map(x => x.toString(16).padStart(2, '0')).join(''); }

  async function init() {
    await _getMlkem();
    _getSm2();
    _ready = true;
    return { ready: true };
  }

  /**
   * Full SM2+ML-KEM-768 hybrid exchange:
   *   1. GET /api/pqc-hybrid/init → server sm2PublicKey + mlkemPublicKey
   *   2. Client: generate ephemeral SM2 keypair → ECDH(server_sm2_pk, client_sk)
   *   3. Client: ML-KEM encapsulate(server_mlkem_pk) → (ct, ss_mlkem)
   *   4. POST /api/pqc-hybrid/finalize → { clientSm2PubHex, mlkemCiphertext }
   *   5. Client deriv: sessionKey = HKDF(tlsSessionId, sm2_ss || mlkem_ss)
   */
  async function doHybridExchange() {
    if (!_ready) await init();

    const mlkem = await _getMlkem();
    const sm2 = _getSm2();

    // Step 1: Get server's SM2 + ML-KEM public keys
    const initRes = await fetch('/api/pqc-hybrid/init', { credentials: 'include' });
    if (!initRes.ok) {
      const e = await initRes.json().catch(() => ({}));
      throw new Error('PQC init failed: ' + (e.error || initRes.status));
    }
    const { sessionId, sm2PublicKey, mlkemPublicKey } = await initRes.json();
    if (!sm2PublicKey || !mlkemPublicKey) throw new Error('Server returned incomplete public keys');

    // Step 2: SM2 ECDH — generate ephemeral keypair, compute shared x-coordinate
    const clientSm2Kp = sm2.generateKeyPair();
    // Server's SM2 public key is hex (128 chars: x||y)
    const serverSm2X = sm2.hexToBigInt ? sm2.hexToBigInt(sm2PublicKey.substring(0, 64))
                     : BigInt('0x' + sm2PublicKey.substring(0, 64));
    const serverSm2Y = sm2.hexToBigInt ? sm2.hexToBigInt(sm2PublicKey.substring(64, 128))
                     : BigInt('0x' + sm2PublicKey.substring(64, 128));
    const serverSm2Point = { x: serverSm2X, y: serverSm2Y };
    const sm2SharedPoint = sm2.pointMultiply(clientSm2Kp.privateKey, serverSm2Point);
    const sm2SsHex = sm2.bigIntToHex
      ? sm2.bigIntToHex(sm2SharedPoint.x).padStart(64, '0')
      : sm2SharedPoint.x.toString(16).padStart(64, '0');

    // Client's SM2 public key hex (to send to server)
    const clientSm2PubHex = sm2.publicKeyToHex
      ? sm2.publicKeyToHex(clientSm2Kp.publicKey)
      : sm2.bigIntToHex(clientSm2Kp.publicKey.x).padStart(64, '0') +
        sm2.bigIntToHex(clientSm2Kp.publicKey.y).padStart(64, '0');

    // Step 3: ML-KEM encapsulate
    const mlkemPkBytes = hexToBytes(mlkemPublicKey);
    const { ciphertext: mlkemCt, sharedSecret: mlkemSs } = mlkem.encapsulate(mlkemPkBytes);

    // Step 4: Send to server — client SM2 pub + ML-KEM ciphertext
    const finRes = await fetch('/api/pqc-hybrid/finalize', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify({
        sessionId,
        clientSm2PubHex,
        mlkemCiphertext: bytesToHex(mlkemCt)
      })
    });
    if (!finRes.ok) {
      const e = await finRes.json().catch(() => ({}));
      throw new Error('PQC finalize failed: ' + (e.error || finRes.status));
    }
    const { confirmed } = await finRes.json();

    // Step 5: Derive mixed session key
    const tlsSessionIdBytes = hexToBytes(sessionId);
    const ikm = new Uint8Array([
      ...hexToBytes(sm2SsHex),
      ...new Uint8Array(mlkemSs)
    ]);
    const prk = await _hkdfExtract(tlsSessionIdBytes, ikm);
    const sessionKey = await _hkdfExpand(prk, new TextEncoder().encode('FIBEMATE_SM2_MLKEM_HYBRID_v1'), 32);

    return {
      sessionKey: bytesToHex(sessionKey),
      sessionId,
      confirmed,
      algorithm: 'SM2+ML-KEM-768',
      ianaRef: '#4590'
    };
  }

  return { init, doHybridExchange };
})();
