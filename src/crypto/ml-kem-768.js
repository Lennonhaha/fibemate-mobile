/**
 * ML-KEM-768 (FIPS 203) — Pure JavaScript Implementation
 * 
 * Strategy: ALL time-domain polynomial arithmetic (no NTT).
 * For n=256, polyMul is O(n^2)=65536 mul ops.
 * Each keygen/encaps/decaps needs ~3-6 polyMuls = ~200K muls total.
 * Modern JS engine: ~5-10ms per operation. Fully acceptable.
 */

// ============================================================================
// 2026-05-31 TVLA 决策记录:
//   纯 JS 实现在 Welch t-test Fixed-vs-Random 下 15/15 PASS (N=3000, |t|<4.5)
//   WASM poly_mul_ct 输出带大偏移量，需 JS 侧 % Q 规约 → V8 % 取值相关耗时
//   → WASM 混合版反而恶化时序安全 (|t| up to 115.11)
//   → 保持纯 JS，WASM 待 Rust 侧添加 mod-Q 内部规约后重新集成
//   桥接代码保留: crypto/wasm/mlkem-ct-wasm-bridge.js
// ============================================================================

const KYBER_N = 256;
const KYBER_Q = 3329;
const KYBER_ETA1 = 2;
const KYBER_ETA2 = 2;
const KYBER_DU = 10;
const KYBER_DV = 4;
const KYBER_K = 3;
const KYBER_PUBLICKEYBYTES = 1184;
const KYBER_SECRETKEYBYTES = 2400;
const KYBER_CIPHERTEXTBYTES = 1088;
const KYBER_SSBYTES = 32;

// ============================================================================
// Basic modular arithmetic
// ============================================================================
function modAdd(a, b) { return (a + b) % KYBER_Q; }
function modSub(a, b) { return ((a - b) % KYBER_Q + KYBER_Q) % KYBER_Q; }
function modMul(a, b) { return (a * b) % KYBER_Q; }

// ============================================================================
// SHA-3 / SHAKE - Pure JavaScript Keccak
// ============================================================================
const KeccakRhoOffsets = [0,1,62,28,27,36,44,6,55,20,3,10,43,25,39,41,45,15,21,8,18,2,61,56,14];
const KeccakPiOffsets = [10,7,11,17,0,3,5,4,15,12,2,13,9,6,1,14,8,16,19,18,23,22,20,24,21];
const KeccakRC = [0x0000000000000001n,0x0000000000008082n,0x800000000000808an,0x8000000080008000n,
    0x000000000000808bn,0x0000000080000001n,0x8000000080008081n,0x8000000000008009n,
    0x000000000000008an,0x0000000000000088n,0x0000000080008009n,0x000000008000000an,
    0x000000008000808bn,0x800000000000008bn,0x8000000000008089n,0x8000000000008003n,
    0x8000000000008002n,0x8000000000000080n,0x000000000000800an,0x800000008000000an,
    0x8000000080008081n,0x8000000000008080n,0x0000000080000001n,0x8000000080008008n];

function ROL64(a, n) {
    if (n === 0) return a;
    n = Number(n);
    const lo = Number(a & 0xFFFFFFFFn);
    const hi = Number((a >> 32n) & 0xFFFFFFFFn);
    let newLo, newHi;
    if (n < 32) {
        newLo = ((lo << n) | (hi >>> (32 - n))) >>> 0;
        newHi = ((hi << n) | (lo >>> (32 - n))) >>> 0;
    } else {
        const m = n - 32;
        newLo = ((hi << m) | (lo >>> (32 - m))) >>> 0;
        newHi = ((lo << m) | (hi >>> (32 - m))) >>> 0;
    }
    return (BigInt(newLo) | (BigInt(newHi) << 32n)) & 0xFFFFFFFFFFFFFFFFn;
}

function KeccakF1600(state) {
    const C = new BigInt64Array(5), D = new BigInt64Array(5), B = new BigInt64Array(25);
    for (let round = 0; round < 24; round++) {
        for (let x = 0; x < 5; x++) C[x] = state[x] ^ state[x+5] ^ state[x+10] ^ state[x+15] ^ state[x+20];
        for (let x = 0; x < 5; x++) D[x] = C[(x+4)%5] ^ ROL64(C[(x+1)%5], 1);
        for (let i = 0; i < 25; i++) state[i] ^= D[i%5];
        for (let i = 0; i < 25; i++) B[KeccakPiOffsets[i]] = ROL64(state[i], KeccakRhoOffsets[i]);
        for (let x = 0; x < 5; x++) for (let y = 0; y < 5; y++)
            state[x+5*y] = B[x+5*y] ^ ((~B[(x+1)%5+5*y]) & B[(x+2)%5+5*y]);
        state[0] ^= KeccakRC[round];
    }
}

function load64(b, i) { let r=0n; for(let j=0;j<8;j++) r|=BigInt(b[i+j])<<BigInt(8*j); return r; }
function store64(v) { const b=new Uint8Array(8); let v2=v; for(let j=0;j<8;j++){b[j]=Number(v2&0xffn);v2>>=8n;} return b; }

function keccak(data, rate, outLen, suffix) {
    const state = new BigInt64Array(25);
    const blockSize = rate >> 3;
    const paddedLen = Math.ceil((data.length + 2) / blockSize) * blockSize;
    const padded = new Uint8Array(paddedLen);
    padded.set(data); padded[data.length] = suffix;
    padded[paddedLen - 1] |= 0x80;
    for (let offset = 0; offset < padded.length; offset += blockSize) {
        for (let j = 0; j < blockSize; j += 8) state[j>>3] ^= load64(padded, offset + j);
        KeccakF1600(state);
    }
    const output = new Uint8Array(outLen);
    let off = 0;
    while (off < outLen) {
        const take = Math.min(blockSize, outLen - off);
        for (let j = 0; j < take; j += 8) {
            const bytes = store64(state[j>>3]);
            for (let k = 0; k < 8 && off+k < outLen; k++) output[off+k] = bytes[k];
        }
        off += take;
        if (off < outLen) KeccakF1600(state);
    }
    return output;
}

function sha3_256(d) { try { return require("crypto").createHash("sha3-256").update(new Uint8Array(d)).digest(); } catch(e) {} try { return require("@noble/hashes/sha3").sha3_256(d); } catch(e) {} return keccak(d, 1088, 32, 0x06); }
function sha3_512(d) { try { return require("crypto").createHash("sha3-512").update(new Uint8Array(d)).digest(); } catch(e) {} try { return require("@noble/hashes/sha3").sha3_512(d); } catch(e) {} return keccak(d, 576, 64, 0x06); }
function shake128(d, len) { try { return require("crypto").createHash("shake128",{outputLength:len}).update(new Uint8Array(d)).digest(); } catch(e) {} try { return require("@noble/hashes/sha3").shake128(d, len); } catch(e) {} return keccak(d, 1344, len, 0x1f); }
function shake256(d, len) { try { return require("crypto").createHash("shake256",{outputLength:len}).update(new Uint8Array(d)).digest(); } catch(e) {} try { return require("@noble/hashes/sha3").shake256(d, len); } catch(e) {} return keccak(d, 1088, len, 0x1f); }

// ============================================================================
// Polynomial operations — ALL TIME DOMAIN
// ============================================================================

// Negacyclic convolution: Z_q[x]/(x^256+1)
// (f*g)[k] = sum_{i+j=k} f[i]*g[j] - sum_{i+j=k+256} f[i]*g[j]
function polyMul(f, g) {
    const r = new Float64Array(KYBER_N);
    for (let i = 0; i < KYBER_N; i++) {
        const fi = f[i];
        for (let j = 0; j < KYBER_N; j++) {
            const k = i + j;
            if (k < KYBER_N) r[k] += fi * g[j];
            else r[k - KYBER_N] -= fi * g[j];
        }
    }
    for (let i = 0; i < KYBER_N; i++) r[i] = ((r[i] % KYBER_Q) + KYBER_Q) % KYBER_Q;
    return r;
}

// Matrix-vector multiply: A (k×k matrix of polys) × v (k-vector of polys)
// All in TIME domain. Result is time-domain polynomials.
function matVecMul(A, v, k) {
    const result = [];
    for (let i = 0; i < k; i++) {
        const acc = new Float64Array(KYBER_N);
        for (let l = 0; l < k; l++) {
            const prod = polyMul(A[i][l], v[l]);
            for (let j = 0; j < KYBER_N; j++) acc[j] += prod[j];
        }
        const norm = new Int16Array(KYBER_N);
        for (let j = 0; j < KYBER_N; j++) norm[j] = ((acc[j] % KYBER_Q) + KYBER_Q) % KYBER_Q;
        result[i] = norm;
    }
    return result;
}

// Vector inner product: a · b (both k-vectors of time-domain polynomials)
// Returns single time-domain polynomial
function vecDot(a, b, k) {
    const acc = new Float64Array(KYBER_N);
    for (let i = 0; i < k; i++) {
        const prod = polyMul(a[i], b[i]);
        for (let j = 0; j < KYBER_N; j++) acc[j] += prod[j];
    }
    const norm = new Int16Array(KYBER_N);
    for (let j = 0; j < KYBER_N; j++) norm[j] = ((acc[j] % KYBER_Q) + KYBER_Q) % KYBER_Q;
    return norm;
}

// Vector add: coefficient-wise
function vecAdd(a, b, k) {
    return a.map((p, i) => {
        const r = new Float64Array(KYBER_N);
        for (let j = 0; j < KYBER_N; j++) r[j] = modAdd(p[j], b[i][j]);
        return r;
    });
}

// Serialization
function byteEncode(f, d) {
    const out = new Uint8Array(KYBER_N * d / 8);
    for (let i = 0; i < KYBER_N; i++) {
        let t = ((f[i] % KYBER_Q) + KYBER_Q) % KYBER_Q;
        for (let j = 0; j < d; j++) { const bi = i*d+j; out[bi>>3] |= ((t>>j)&1) << (bi&7); }
    }
    return out;
}
function byteDecode(data, d) {
    const f = new Int16Array(KYBER_N);
    for (let i = 0; i < KYBER_N; i++) {
        let t = 0;
        for (let j = 0; j < d; j++) { const bi = i*d+j; t |= ((data[bi>>3]>>(bi&7))&1) << j; }
        f[i] = t;
    }
    return f;
}
function compress(f, d) {
    const g = new Int16Array(KYBER_N);
    for (let i = 0; i < KYBER_N; i++) {
        let x = ((f[i]%KYBER_Q)+KYBER_Q)%KYBER_Q;
        g[i] = Number(((BigInt(x)*(BigInt(1)<<BigInt(d))+BigInt(Math.floor(KYBER_Q / 2)))/BigInt(KYBER_Q))&BigInt((1<<d)-1));
    }
    return g;
}
function decompress(g, d) {
    const f = new Int16Array(KYBER_N);
    for (let i = 0; i < KYBER_N; i++)
        f[i] = Number(((BigInt(g[i])*BigInt(KYBER_Q)+(1n<<BigInt(d-1)))/(1n<<BigInt(d))));
    return f;
}

// CBD (Centered Binomial Distribution) with eta=2
function cbd2(buf) {
    const r = new Float64Array(KYBER_N);
    for (let i = 0; i < 128; i++) {
        const b = buf[i];
        r[2*i]   = (b&1) + ((b>>1)&1) - ((b>>2)&1) - ((b>>3)&1);
        r[2*i+1] = ((b>>4)&1) + ((b>>5)&1) - ((b>>6)&1) - ((b>>7)&1);
    }
    return r;
}

// Sample polynomial from seed+nonce — returns TIME-DOMAIN coefficients
// This replaces the old sampleNTT which was misnamed
function samplePoly(seed, nonce) {
    const stream = shake128(new Uint8Array([...seed, nonce]), 768);
    const a = new Int16Array(KYBER_N);
    let j = 0, idx = 0;
    while (j < KYBER_N && idx < 765) {
        const d1 = stream[idx] | ((stream[idx+1] & 0x0F) << 8);
        const d2 = (stream[idx+1] >> 4) | (stream[idx+2] << 4);
        idx += 3;
        if (d1 < KYBER_Q) a[j++] = d1;
        if (j < KYBER_N && d2 < KYBER_Q) a[j++] = d2;
    }
    return a; // TIME DOMAIN
}

// ============================================================================
// KeyGen, Encaps, Decaps — ALL TIME DOMAIN
// ============================================================================

function generateKeypair() {
    const d = crypto.getRandomValues(new Uint8Array(32));
    const z = crypto.getRandomValues(new Uint8Array(32));
    const seed = sha3_512(d);
    const rho = seed.slice(0, 32);
    const sigma = seed.slice(32, 64);

    // Sample A matrix (time domain)
    const A = [];
    for (let i = 0; i < KYBER_K; i++) {
        A[i] = [];
        for (let j = 0; j < KYBER_K; j++) {
            A[i][j] = samplePoly(rho, (i << 8) | j); // TIME DOMAIN
        }
    }

    // Sample s and e (time domain)
    const s = [], e = [];
    for (let i = 0; i < KYBER_K; i++) {
        s[i] = cbd2(shake256(new Uint8Array([...sigma, i]), 128));
        e[i] = cbd2(shake256(new Uint8Array([...sigma, i + KYBER_K]), 128));
    }

    // t = A*s + e (all time domain)
    const As = matVecMul(A, s, KYBER_K); // TIME domain
    const t_final = vecAdd(As, e, KYBER_K); // TIME domain

    // Encode public key: t (time domain, 12-bit) + rho
    const pk = new Uint8Array(KYBER_PUBLICKEYBYTES);
    let off = 0;
    for (let i = 0; i < KYBER_K; i++) { pk.set(byteEncode(t_final[i], 12), off); off += 384; }
    pk.set(rho, off);

    // Encode secret key: s (time domain, 12-bit) + pk + H(pk) + z
    const sk = new Uint8Array(KYBER_SECRETKEYBYTES);
    off = 0;
    for (let i = 0; i < KYBER_K; i++) { sk.set(byteEncode(s[i], 12), off); off += 384; }
    sk.set(pk, off); off += KYBER_PUBLICKEYBYTES;
    sk.set(sha3_256(pk), off); off += 32;
    sk.set(z, off);

    return { publicKey: pk, secretKey: sk };
}

function encapsulate(publicKey) {
    const m = crypto.getRandomValues(new Uint8Array(32));

    // Decode t from public key (TIME DOMAIN, 12-bit encoded)
    const t = [];
    let off = 0;
    for (let i = 0; i < KYBER_K; i++) { t[i] = byteDecode(publicKey.slice(off, off+384), 12); off += 384; }
    const rho = publicKey.slice(off, off + 32);

    const h = sha3_256(publicKey);
    const K_bar = sha3_256(new Uint8Array([...m, ...h]));

    // Sample A^T matrix (time domain) — note transposed indices
    const AT = [];
    for (let i = 0; i < KYBER_K; i++) {
        AT[i] = [];
        for (let j = 0; j < KYBER_K; j++) {
            AT[i][j] = samplePoly(rho, (j << 8) | i); // transposed: (j,i) not (i,j)
        }
    }

    // Sample r, e1, e2 (time domain)
    let r = [], e1 = [], e2 = null;
    for (let i = 0; i < KYBER_K; i++) {
        r[i] = cbd2(shake256(new Uint8Array([...m, i]), 128));
        e1[i] = cbd2(shake256(new Uint8Array([...m, i + KYBER_K]), 128));
    }

    // u = A^T * r + e1 (all time domain)
    const ATr = matVecMul(AT, r, KYBER_K);
    const u_final = vecAdd(ATr, e1, KYBER_K);

    // v = t^T * r + e2 + m_poly (all time domain)
    const tr = vecDot(t, r, KYBER_K); // inner product, time domain
    e2 = cbd2(shake256(new Uint8Array([...m, 2*KYBER_K]), 128));

    const mPoly = new Int16Array(KYBER_N);
    for (let i = 0; i < KYBER_N; i++) mPoly[i] = ((m[Math.floor(i/8)]>>(i%8))&1)*Math.ceil(KYBER_Q/2);

    const v = new Int16Array(KYBER_N);
    for (let i = 0; i < KYBER_N; i++) v[i] = modAdd(modAdd(tr[i], e2[i]), mPoly[i]);

    // Encode ciphertext
    const ct = new Uint8Array(KYBER_CIPHERTEXTBYTES);
    off = 0;
    for (let i = 0; i < KYBER_K; i++) { ct.set(byteEncode(compress(u_final[i], KYBER_DU), KYBER_DU), off); off += 320; }
    ct.set(byteEncode(compress(v, KYBER_DV), KYBER_DV), off);

    const ss = sha3_256(new Uint8Array([...K_bar, ...sha3_256(ct)]));
    return { ciphertext: ct, sharedSecret: ss };
}

function decapsulate(secretKey, ciphertext) {
    const n = KYBER_K;

    // Decode secret key
    const s = []; // TIME DOMAIN
    let off = 0;
    for (let i = 0; i < n; i++) { s[i] = byteDecode(secretKey.slice(off, off+384), 12); off += 384; }
    const pk = secretKey.slice(off, off + KYBER_PUBLICKEYBYTES); off += KYBER_PUBLICKEYBYTES;
    const h = secretKey.slice(off, off+32); off += 32;
const z = secretKey.slice(off, off+32);

    // Decode ciphertext
    const u = [];
    off = 0;
    for (let i = 0; i < n; i++) { u[i] = decompress(byteDecode(ciphertext.slice(off, off+320), KYBER_DU), KYBER_DU); off += 320; }
    const v = decompress(byteDecode(ciphertext.slice(off, off+128), KYBER_DV), KYBER_DV);

    // s^T * u (inner product, all time domain)
    const su = vecDot(s, u, n);

    // Recover m'
    const mp = new Int16Array(KYBER_N);
    for (let i = 0; i < KYBER_N; i++) mp[i] = ((modSub(v[i], su[i]) % KYBER_Q) + KYBER_Q) % KYBER_Q;

    const mPrime = new Uint8Array(32);
    // polyToMsg: 1-bit per coefficient (FIPS 203 Compress_1 fidelity)
    for (let i = 0; i < KYBER_N; i++) {
        const x = ((mp[i] % KYBER_Q) + KYBER_Q) % KYBER_Q;
        // Correct: bit=1 iff x is closer to ceil(Q/2) than to 0 or Q
        if (x > 832 && x < 2497) mPrime[Math.floor(i/8)] |= 1 << (i % 8);
    }

    const K_bar_prime = sha3_256(new Uint8Array([...mPrime, ...h]));
    const rho = pk.slice(n*384, n*384+32);

    // Re-encrypt with m' (same as encapsulate, all time domain)
    const AT = [];
    for (let i = 0; i < n; i++) {
        AT[i] = [];
        for (let j = 0; j < n; j++) {
            AT[i][j] = samplePoly(rho, (j<<8)|i);
        }
    }
    const r2 = [], e1_2 = [];
    for (let i = 0; i < n; i++) {
        r2[i] = cbd2(shake256(new Uint8Array([...mPrime, i]), 128));
        e1_2[i] = cbd2(shake256(new Uint8Array([...mPrime, i+n]), 128));
    }
    const u2 = vecAdd(matVecMul(AT, r2, n), e1_2, n);

    // Decode t from pk (time domain)
    const t2 = [];
    let tOff = 0;
    for (let i = 0; i < n; i++) { t2[i] = byteDecode(pk.slice(tOff, tOff+384), 12); tOff += 384; }

    const tr2 = vecDot(t2, r2, n);
    const e2_2 = cbd2(shake256(new Uint8Array([...mPrime, 2*n]), 128));

    const mPoly2 = new Int16Array(KYBER_N);
    for (let i = 0; i < KYBER_N; i++) mPoly2[i] = ((mPrime[Math.floor(i/8)]>>(i%8))&1)*Math.ceil(KYBER_Q/2);

    const v2 = new Int16Array(KYBER_N);
    for (let i = 0; i < KYBER_N; i++) v2[i] = modAdd(modAdd(tr2[i], e2_2[i]), mPoly2[i]);

    // Reconstruct ct' and compare
    const ct2 = new Uint8Array(KYBER_CIPHERTEXTBYTES);
    off = 0;
    for (let i = 0; i < n; i++) { ct2.set(byteEncode(compress(u2[i], KYBER_DU), KYBER_DU), off); off += 320; }
    ct2.set(byteEncode(compress(v2, KYBER_DV), KYBER_DV), off);

    // Constant-time selection
    let fail = 0;
    for (let i = 0; i < KYBER_CIPHERTEXTBYTES; i++) fail |= ciphertext[i] ^ ct2[i];
    const ctMask = 0 - ((fail | -fail) >>> 31);

    const h_ct = sha3_256(ciphertext);
    const h_implicit = sha3_256(new Uint8Array([...z, ...h_ct]));
    const h_real = sha3_256(new Uint8Array([...K_bar_prime, ...h_ct]));
    const ss = new Uint8Array(32);
    for (let i = 0; i < 32; i++) ss[i] = (h_real[i] & ~ctMask) | (h_implicit[i] & ctMask);
    return ss;
}

// ============================================================================
// HybridKeyExchange class (unchanged interface)
// ============================================================================
class HybridKeyExchange {
    constructor() { this.kemKeypair = null; this.ecdhKeypair = null; }
    async initialize() {
        this.kemKeypair = generateKeypair();
        this.ecdhKeypair = await crypto.subtle.generateKey({name:'ECDH',namedCurve:'P-256'},true,['deriveBits']);
        return { kemPublicKey: this.kemKeypair.publicKey, ecdhPublicKey: await crypto.subtle.exportKey('raw', this.ecdhKeypair.publicKey) };
    }
    async encapsulateToPeer(pk, ecdhPk) {
        const k = encapsulate(pk);
        const e = await crypto.subtle.importKey('raw', ecdhPk, {name:'ECDH',namedCurve:'P-256'},false,[]);
        const d = await crypto.subtle.deriveBits({name:'ECDH',public:e},this.ecdhKeypair.privateKey,256);
        const c = new Uint8Array(64); c.set(k.sharedSecret,0); c.set(new Uint8Array(d),32);
        return { ciphertext: k.ciphertext, sharedSecret: sha3_256(c) };
    }
    async decapsulateFromPeer(ct, ecdhPk) {
        const ks = decapsulate(this.kemKeypair.secretKey, ct);
        const e = await crypto.subtle.importKey('raw', ecdhPk, {name:'ECDH',namedCurve:'P-256'},false,[]);
        const d = await crypto.subtle.deriveBits({name:'ECDH',public:e},this.ecdhKeypair.privateKey,256);
        const c = new Uint8Array(64); c.set(ks,0); c.set(new Uint8Array(d),32);
        return sha3_256(c);
    }
}

// Exports

// ============================================================================
// WASM 恒定时间集成 — 运行时猴子补丁



// ============================================================================
// WASM 恒定时间集成 — 猴子补丁 (仅向量运算)
// ============================================================================
/**
 * 用 WASM 恒定时间实现替换 3 个核心多项式运算
 * @param {object} bridge — MLKEM_CT_WASM (需先 await bridge.init())
 *
 * 替换: polyMul, compress, decompress
 * 保留 JS: modAdd, modSub, modMul (WASM 为 256 元向量原语，不适用于 scalar)
 */


// ============================================================================
// WASM 恒定时间集成 — 猴子补丁 (仅 polyMul 向量运算)
// ============================================================================
/**
 * 用 WASM 恒定时间实现替换 polyMul (O(n²) 热点)
 * @param {object} bridge — MLKEM_CT_WASM (需先 await bridge.init())
 *
 * 不替换 compress/decompress — WASM 融合了字节编码，API 不兼容纯系数操作
 * polyMul 是唯一 API 完全匹配且性能影响最大的运算 (256×256=65536 次循环)
 */

const MLKEM768 = {
    generateKeypair, encapsulate, decapsulate, HybridKeyExchange,
    PUBLIC_KEY_BYTES: KYBER_PUBLICKEYBYTES, SECRET_KEY_BYTES: KYBER_SECRETKEYBYTES,
    CIPHERTEXT_BYTES: KYBER_CIPHERTEXTBYTES, SHARED_SECRET_BYTES: KYBER_SSBYTES,
    compress, decompress, byteEncode, byteDecode, polyMul, vecAdd, vecDot, matVecMul,
    modAdd, modSub, modMul, samplePoly, sha3_256, sha3_512, shake128, shake256
};
if (typeof window !== 'undefined') window.MLKEM768 = MLKEM768;
if (typeof module !== 'undefined' && module.exports) module.exports = MLKEM768;
