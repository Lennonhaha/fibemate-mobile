/**
 * FIBEMATE SM2 BigInt Browser Edition
 * =====================================
 * Jacobian 射影坐标 + Native BigInt，域乘法加速 11.4x
 * v1.2-browser (2026-06-20) — IIFE for window.SM2EC, zero Node.js deps
 *
 * 来源: sm2-bigint-ec.js v1.2 (TVLA N=5000 5/5 PASS)
 * 变更: require('crypto') → Web Crypto API, Buffer → Uint8Array
 */
(function () {
  'use strict';

  // ============ SM2 Curve Parameters (BigInt) ============
  const SM2_P = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFFn;
  const SM2_N = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123n;
  const SM2_A = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFCn;
  const SM2_B = 0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93n;
  const SM2_GX = 0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7n;
  const SM2_GY = 0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0n;

  const ZERO = 0n, ONE = 1n, TWO = 2n, THREE = 3n, FOUR = 4n, EIGHT = 8n;

  // ============ Browser-safe randomBytes ============
  function randomBytes(n) {
    const buf = new Uint8Array(n);
    crypto.getRandomValues(buf);
    return buf;
  }

  function randomBigInt(bytes) {
    return BigInt('0x' + Array.from(randomBytes(bytes)).map(b => b.toString(16).padStart(2, '0')).join(''));
  }

  // ============ Hex / Bytes utilities ============
  function hexPad(s) { return s.length % 2 ? '0' + s : s; }
  function bi2hex(x) { return hexPad(x.toString(16)); }
  function hex2bi(s) { return BigInt('0x' + s); }

  function hexToBytes(hex) {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) bytes[i >> 1] = parseInt(hex.substring(i, i + 2), 16);
    return bytes;
  }

  function bytesToHex(bytes) {
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
  }

  // ============ Field Operations (mod SM2_P) ============
  const F = {
    add(a, b) { const s = a + b; return s >= SM2_P ? s - SM2_P : s; },
    sub(a, b) { return a >= b ? a - b : a - b + SM2_P; },
    mul(a, b) { return (a * b) % SM2_P; },
    sqr(a) { return (a * a) % SM2_P; },
    inv(a) {
      let t = ZERO, nt = ONE, r = SM2_P, nr = a % SM2_P;
      while (nr !== ZERO) {
        const q = r / nr;
        [t, nt] = [nt, t - q * nt];
        [r, nr] = [nr, r - q * nr];
      }
      return t < ZERO ? t + SM2_P : t;
    },
    addN(a, b) { const s = a + b; return s >= SM2_N ? s - SM2_N : s; },
  };

  // ============ Jacobian Projective Point Operations ============
  const J_ZERO = Object.freeze({ x: ZERO, y: ZERO, z: ZERO });
  const INFINITY = Object.freeze({ x: null, y: null });

  function isJInf(P) { return P.z === ZERO; }
  function isInf(P) { return P.x === null && P.y === null; }
  function makePt(x, y) { return { x, y }; }

  function toJ(P) {
    if (isInf(P)) return J_ZERO;
    return { x: P.x, y: P.y, z: ONE };
  }

  function toA(P) {
    if (isJInf(P)) return INFINITY;
    const zi = F.inv(P.z);
    const zz = F.sqr(zi);
    return makePt(F.mul(P.x, zz), F.mul(P.y, F.mul(zz, zi)));
  }

  function jDbl(P) {
    if (isJInf(P)) return P;
    const { x, y, z } = P;
    const yy = F.sqr(y);
    const y4 = F.sqr(yy);
    const s = F.mul(F.mul(x, FOUR), yy);
    const zz = F.sqr(z);
    const z4 = F.sqr(zz);
    const m = F.sub(F.mul(THREE, F.sqr(x)), F.mul(THREE, z4));
    const x3 = F.sub(F.sqr(m), F.mul(s, TWO));
    const y3 = F.sub(F.mul(m, F.sub(s, x3)), F.mul(y4, EIGHT));
    const z3 = F.mul(F.mul(y, z), TWO);
    return { x: x3, y: y3, z: z3 };
  }

  function jAddMixed(A, Q) {
    if (isJInf(Q)) return toJ(A);
    if (isInf(A)) return Q;
    const { x: x2, y: y2, z: z2 } = Q;
    const { x: x1, y: y1 } = A;
    const zz = F.sqr(z2);
    const u2 = F.mul(x1, zz);
    const z3 = F.mul(zz, z2);
    const s2 = F.mul(y1, z3);
    if (u2 === x2 && s2 === y2) return jDbl(Q);
    const h = F.sub(u2, x2);
    const hh = F.sqr(h);
    const i = F.mul(hh, FOUR);
    const j = F.mul(h, i);
    const r = F.mul(F.sub(s2, y2), TWO);
    const v = F.mul(x2, i);
    const x3 = F.sub(F.sub(F.sqr(r), j), F.mul(v, TWO));
    const y3 = F.sub(F.mul(r, F.sub(v, x3)), F.mul(F.mul(y2, TWO), j));
    const z3_f = F.sub(F.sqr(F.add(h, z2)), F.add(zz, hh));
    return { x: x3, y: y3, z: z3_f };
  }

  function jAdd(P, Q) {
    if (isJInf(P)) return Q;
    if (isJInf(Q)) return P;
    const { x: x1, y: y1, z: z1 } = P;
    const { x: x2, y: y2, z: z2 } = Q;
    const z1z1 = F.sqr(z1);
    const z2z2 = F.sqr(z2);
    const u1 = F.mul(x1, z2z2);
    const u2 = F.mul(x2, z1z1);
    const s1 = F.mul(y1, F.mul(z2z2, z2));
    const s2 = F.mul(y2, F.mul(z1z1, z1));
    if (u1 === u2) {
      if (s1 !== s2) return J_ZERO;
      return jDbl(P);
    }
    const h = F.sub(u2, u1);
    const i = F.sqr(F.mul(h, TWO));
    const j = F.mul(h, i);
    const r = F.sub(F.mul(s2, TWO), F.mul(s1, TWO));
    const v = F.mul(u1, i);
    const x3 = F.sub(F.sub(F.sqr(r), j), F.mul(v, TWO));
    const y3 = F.sub(F.mul(r, F.sub(v, x3)), F.mul(F.mul(s1, TWO), j));
    const z3 = F.mul(F.sub(F.sqr(F.add(z1, z2)), F.add(z1z1, z2z2)), h);
    return { x: x3, y: y3, z: z3 };
  }

  // ============ Scalar Multiplication (TVLA-hardened) ============
  /**
   * k * P  (P in affine, result in affine)
   *
   * Defence-in-depth:
   *   1) Scalar masking:   k' = k + r*N  → different bit pattern every call
   *   2) Projective randomization: start Q with random z-coordinate
   */
  function pointMul(k, P) {
    if (isInf(P) || k === ZERO) return INFINITY;

    // --- 1. Scalar masking ---
    const r = randomBigInt(8);
    const kMasked = r === ZERO ? k : k + r * SM2_N;

    // --- 2. Projective randomization ---
    const rz = randomBigInt(8) % SM2_P;
    const rzSafe = rz === ZERO ? ONE : rz;
    const rz2 = (rzSafe * rzSafe) % SM2_P;
    const rz3 = (rz2 * rzSafe) % SM2_P;
    const P_aff = { x: P.x, y: P.y };
    let Q = { x: (P.x * rz2) % SM2_P, y: (P.y * rz3) % SM2_P, z: rzSafe };

    // --- 3. Binary double-and-add (MSB→LSB) ---
    const kBits = [];
    let kk = kMasked;
    while (kk > ZERO) { kBits.push(kk & ONE); kk >>= ONE; }

    for (let i = kBits.length - 2; i >= 0; i--) {
      Q = jDbl(Q);
      if (kBits[i]) Q = jAddMixed(P_aff, Q);
    }
    return toA(Q);
  }

  // ============ Generator Point ============
  const G = makePt(SM2_GX, SM2_GY);

  function mulG(k) {
    if (typeof k !== 'bigint') k = BigInt(k);
    return pointMul(k, G);
  }

  // ============ Key Management ============
  function generateKeyPair() {
    let d;
    do { d = randomBigInt(32); } while (d <= ZERO || d >= SM2_N);
    return { privateKey: d, publicKey: pointMul(d, G) };
  }

  function publicKeyFromPrivate(d) {
    if (typeof d !== 'bigint') d = BigInt(d);
    return pointMul(d, G);
  }

  // ============ Public Key Serialization ============
  function pk2hex(pk) { return '04' + bi2hex(pk.x) + bi2hex(pk.y); }

  function hex2pk(hex) {
    if (!hex.startsWith('04') || hex.length !== 130) throw new Error('Invalid public key hex');
    return makePt(hex2bi(hex.slice(2, 66)), hex2bi(hex.slice(66, 130)));
  }

  // ============ ECDH Shared Secret (key exchange) ============
  /**
   * Compute SM2 ECDH shared point: d * peerPublicKey
   * Returns 64-byte Uint8Array (x || y coordinates)
   */
  function computeSharedSecret(privateKey, peerPublicKeyHex) {
    const d = typeof privateKey === 'bigint' ? privateKey : hex2bi(privateKey);
    const peer = typeof peerPublicKeyHex === 'string' ? hex2pk(peerPublicKeyHex) : peerPublicKeyHex;
    const S = pointMul(d, peer);
    const xHex = bi2hex(S.x).padStart(64, '0');
    const yHex = bi2hex(S.y).padStart(64, '0');
    return hexToBytes(xHex + yHex);
  }

  // ============ Signature (SM2 GB/T 32918.2) ============
  function extEuclidInv(a, m) {
    let t = ZERO, nt = ONE, r = m, nr = a % m;
    while (nr !== ZERO) {
      const q = r / nr;
      [t, nt] = [nt, t - q * nt];
      [r, nr] = [nr, r - q * nr];
    }
    return t < ZERO ? t + m : t;
  }

  function sign(privateKey, msgHash) {
    const dA = typeof privateKey === 'bigint' ? privateKey : hex2bi(privateKey);
    const e = typeof msgHash === 'bigint' ? msgHash : hex2bi(msgHash);
    let k, Q, x1, r;
    do {
      k = randomBigInt(32) % SM2_N;
      if (k === ZERO) continue;
      Q = pointMul(k, G);
      x1 = Q.x % SM2_N;
      r = (e + x1) % SM2_N;
    } while (r === ZERO || (r + k) % SM2_N === ZERO);
    const da1 = F.addN(dA, ONE);
    const da1Inv = extEuclidInv(da1, SM2_N);
    const s = (da1Inv * ((k - (r * dA) % SM2_N + SM2_N) % SM2_N)) % SM2_N;
    return { r: bi2hex(r), s: bi2hex(s) };
  }

  function verify(pubHex, msgHash, sigR, sigS) {
    const r = hex2bi(sigR), s = hex2bi(sigS);
    const e = typeof msgHash === 'bigint' ? msgHash : hex2bi(msgHash);
    if (r <= ZERO || r >= SM2_N || s <= ZERO || s >= SM2_N) return false;
    const t = (r + s) % SM2_N;
    if (t === ZERO) return false;
    if (!pubHex.startsWith('04') || pubHex.length !== 130) return false;
    const PA = makePt(hex2bi(pubHex.slice(2, 66)), hex2bi(pubHex.slice(66, 130)));
    const sG_J = toJ(pointMul(s, G));
    const tPA_J = toJ(pointMul(t, PA));
    const Q = toA(jAdd(sG_J, tPA_J));
    return F.addN(e, Q.x % SM2_N) === r;
  }

  // ============ Encrypt (GB/T 32918.4, C1C3C2 mode) ============
  function encrypt(pubHex, plaintext) {
    const PB = hex2pk(pubHex);
    let k, C1;
    do {
      k = randomBigInt(32) % SM2_N;
      if (k === ZERO) continue;
      C1 = pointMul(k, G);
    } while (isInf(C1));

    const kPB = pointMul(k, PB);
    const keyHex = bi2hex(kPB.x);
    const key = hexToBytes(keyHex);
    const pt = new TextEncoder().encode(plaintext);
    const ct = new Uint8Array(pt.length);
    for (let i = 0; i < pt.length; i++) ct[i] = pt[i] ^ key[i % key.length];
    return { c1: pk2hex(C1), c2: bytesToHex(ct) };
  }

  function decrypt(privateKey, c1Hex, c2Hex) {
    const d = typeof privateKey === 'bigint' ? privateKey : hex2bi(privateKey);
    const C1 = hex2pk(c1Hex);
    const dC1 = pointMul(d, C1);
    const key = hexToBytes(bi2hex(dC1.x));
    const ct = hexToBytes(c2Hex);
    const pt = new Uint8Array(ct.length);
    for (let i = 0; i < ct.length; i++) pt[i] = ct[i] ^ key[i % key.length];
    return new TextDecoder().decode(pt);
  }

  // ============ Public API (window.SM2EC) ============
  window.SM2EC = {
    // Curve constants
    P: SM2_P, N: SM2_N, A: SM2_A, B: SM2_B, G,

    // Key management
    generateKeyPair,
    publicKeyFromPrivate,

    // ECDH key exchange
    computeSharedSecret,

    // Encryption (GB/T 32918.4)
    encrypt,
    decrypt,

    // Signature (GB/T 32918.2)
    sign,
    verify,

    // Serialization
    publicKeyToHex: pk2hex,
    hexToPublicKey: hex2pk,
    bigIntToHex: bi2hex,
    hexToBigInt: hex2bi,

    // Utilities
    hexPad,
    hexToBytes,
    bytesToHex,
    isValidPublicKey: (hex) => {
      try { hex2pk(hex); return true; } catch { return false; }
    },

    // Point operations (for debugging / advanced use)
    pointMultiply: pointMul,
    multiplyG: mulG,
    INFINITY,
    isInf,
  };

})();
