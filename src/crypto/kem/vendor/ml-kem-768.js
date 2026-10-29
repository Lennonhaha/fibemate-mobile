// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 FIBEMATE Contributors
// Vendored from fibemate@eb2e262 packages/pqc-kem/src/ml-kem-768.js (Apache-2.0).
// Local changes:
//   1. Hash helpers delegate to @noble/hashes instead of require("crypto") /
//      require("@noble/hashes") fast paths. Metro must not resolve Node builtins, and the
//      bundled Keccak fallback in the upstream file is incorrect (see PR notes).
//   2. Everything else is byte-for-byte upstream; test/kem-clean-break.node.cjs checks the
//      result against @noble/post-quantum on fixed seeds.

/**
 * ML-KEM (FIPS 203) — Pure JavaScript NTT-Domain Implementation
 *
 * NTT encode: DIT butterfly (dit=false→isDit=true), ZETAS[1..127]
 * NTT decode: invertButterflies (dit=true→isDit=false), ZETAS[255..129], ×3303
 * polyMulNTT: BaseCaseMultiply with ZETAS[64+⌊i/2⌋]
 *
 * Cross-validated with @noble/post-quantum ml-kem (200/200 both directions).
 *
 * Algorithm agility (AA): runtime-switchable parameter sets via loadParams()
 *   ML-KEM-512  (k=2, η1=3, η2=2, du=10, dv=4)
 *   ML-KEM-768  (k=3, η1=2, η2=2, du=10, dv=4)
 *   ML-KEM-1024 (k=4, η1=2, η2=2, du=11, dv=5)
 *
 * Use the WASM path for production workloads; this file is for auditability.
 */

'use strict';

const nobleSha3 = require('@noble/hashes/sha3.js');

// Runtime parameter set (AA: algorithm agility — switchable without recompile)
const { getParams, listParamSets, MLKEM_PARAMS } = require('./params');
let _KYBER_N, _KYBER_Q, KYBER_K, _KYBER_ETA1, _KYBER_ETA2, KYBER_DU, KYBER_DV,
    KYBER_PUBLICKEYBYTES, KYBER_SECRETKEYBYTES, KYBER_CIPHERTEXTBYTES, KYBER_SSBYTES, _KYBER_QHALF;
let _currentParamSet = 'ML-KEM-768';

function loadParams(paramSet) {
    const p = getParams(paramSet);
    _KYBER_N = p.N; _KYBER_Q = p.Q; KYBER_K = p.k;
    _KYBER_ETA1 = p.eta1; _KYBER_ETA2 = p.eta2;
    KYBER_DU = p.du; KYBER_DV = p.dv;
    KYBER_PUBLICKEYBYTES = p.ekBytes;
    KYBER_SECRETKEYBYTES = p.dkBytes;
    KYBER_CIPHERTEXTBYTES = p.ctBytes;
    KYBER_SSBYTES = p.ssBytes;
    _KYBER_QHALF = p.qHalf;
    _currentParamSet = paramSet;
}
loadParams(_currentParamSet);  // default: ML-KEM-768

// Detect WebCrypto (globalThis.crypto in browsers, require('crypto').webcrypto in Node)
const _webcrypto = (typeof crypto !== 'undefined' && crypto.getRandomValues) ? crypto : null;

// Fixed ring constants (independent of parameter set k)
const N = 256, Q = 3329, NTT_INV = 3303;

// ============================================================================
// ZETAS[256] — period-128, ZETAS[i]=17^{BR₇(i)} mod 3329
// ============================================================================
const ZETAS = new Int16Array([
      1,1729,2580,3289,2642,630,1897,848,1062,1919,193,797,2786,3260,569,1746,
    296,2447,1339,1476,3046,56,2240,1333,1426,2094,535,2882,2393,2879,1974,821,
    289,331,3253,1756,1197,2304,2277,2055,650,1977,2513,632,2865,33,1320,1915,
   2319,1435,807,452,1438,2868,1534,2402,2647,2617,1481,648,2474,3110,1227,910,
     17,2761,583,2649,1637,723,2288,1100,1409,2662,3281,233,756,2156,3015,3050,
   1703,1651,2789,1789,1847,952,1461,2687,939,2308,2437,2388,733,2337,268,641,
   1584,2298,2037,3220,375,2549,2090,1645,1063,319,2773,757,2099,561,2466,2594,
   2804,1092,403,1026,1143,2150,2775,886,1722,1212,1874,1029,2110,2935,885,2154,
    // repeat
      1,1729,2580,3289,2642,630,1897,848,1062,1919,193,797,2786,3260,569,1746,
    296,2447,1339,1476,3046,56,2240,1333,1426,2094,535,2882,2393,2879,1974,821,
    289,331,3253,1756,1197,2304,2277,2055,650,1977,2513,632,2865,33,1320,1915,
   2319,1435,807,452,1438,2868,1534,2402,2647,2617,1481,648,2474,3110,1227,910,
     17,2761,583,2649,1637,723,2288,1100,1409,2662,3281,233,756,2156,3015,3050,
   1703,1651,2789,1789,1847,952,1461,2687,939,2308,2437,2388,733,2337,268,641,
   1584,2298,2037,3220,375,2549,2090,1645,1063,319,2773,757,2099,561,2466,2594,
   2804,1092,403,1026,1143,2150,2775,886,1722,1212,1874,1029,2110,2935,885,2154,
]);

// ============================================================================
// Constant-time helpers (audit/tvla use only; production WASM path is authoritative)
// ============================================================================
function ctSelectByte(a, b, mask) { return (a & mask) | (b & (0xFF ^ mask)); }

/** Constant-time Uint8Array select. mask=0xFF → ok; 0x00 → reject. */
function ctSelectU8(ok, reject, mask) {
    if (ok.length !== reject.length) throw new RangeError('ctSelectU8 length mismatch');
    const out = new Uint8Array(ok.length);
    for (let i = 0; i < ok.length; i++) out[i] = ctSelectByte(ok[i], reject[i], mask);
    return out;
}

/** Constant-time equality mask: 0xFF if equal, else 0x00. */
function ctEqMask(a, b) {
    if (a.length !== b.length) throw new RangeError('ctEqMask length mismatch');
    let diff = 0;
    for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
    return ((diff - 1) >> 31) & 0xFF;
}

function zeroizeU8(a) { for (let i = 0; i < a.length; i++) a[i] = 0; }
function zeroizeI16(a) { for (let i = 0; i < a.length; i++) a[i] = 0; }
function zeroizePolyVec(v) { for (let i = 0; i < v.length; i++) zeroizeI16(v[i]); }

// ============================================================================
// Modular arithmetic (Barrett reduction — safe for negative inputs)
// ============================================================================
const _BAR_K = 24, BAR_MU = 5039;
function modMulBarrett(a, b) {
    const p = a * b;                         // exact in f64: p < 11,082,241 < 2^24
    const q = Math.floor(p * BAR_MU / 16777216);
    let r = p - q * 3329;
    if (r >= 3329) r -= 3329;
    if (r >= 3329) r -= 3329;
    return r;
}
function modAdd(a, b) { const r = ((a|0)+(b|0)); return r >= Q ? r-Q : r; }
function modSub(a, b) { const r = ((a|0)-(b|0)); return r < 0 ? r+Q : r; }
function modMul(a, b) { return modMulBarrett(((a|0)%Q+Q)%Q, ((b|0)%Q+Q)%Q); }
function modNeg(a) { const na = ((a|0)%Q+Q)%Q; return na ? Q-na : 0; }

// ============================================================================
// NTT / iNTT — 1:1 with @noble/curves FFTCore (genCrystals Kyber mode)
// ============================================================================
function ntt(f) {
    let step = 1;
    for (let s = 8; s > 1; s--) {
        const m = 1<<s, m2 = m>>1;
        for (let k = 0; k < N; k += m) {
            const omega = ZETAS[step++];
            for (let j = 0; j < m2; j++) {
                const i0 = k+j, i1 = k+j+m2;
                const a = f[i0], b = f[i1];
                const t = modMul(b, omega);
                f[i0] = modAdd(a, t);
                f[i1] = modSub(a, t);
            }
        }
    }
    return f;
}

function intt(f) {
    let step = 1;
    for (let s = 2; s <= 8; s++) {
        const m = 1<<s, m2 = m>>1;
        for (let k = 0; k < N; k += m) {
            const omega = ZETAS[256 - step++];
            for (let j = 0; j < m2; j++) {
                const i0 = k+j, i1 = k+j+m2;
                const a = f[i0], b = f[i1];
                f[i0] = modAdd(b, a);
                f[i1] = modMul(modSub(b, a), omega);
            }
        }
    }
    for (let i = 0; i < N; i++) f[i] = modMul(f[i], NTT_INV);
    return f;
}

// ============================================================================
// SHA-3 / SHAKE — pure JS Keccak with noble/crypto fallbacks
// ============================================================================
const KeccakRhoOffsets = [0,1,62,28,27,36,44,6,55,20,3,10,43,25,39,41,45,15,21,8,18,2,61,56,14];
const KeccakPiOffsets = [10,7,11,17,0,3,5,4,15,12,2,13,9,6,1,14,8,16,19,18,23,22,20,24,21];
const KeccakRC = [0x0000000000000001n,0x0000000000008082n,0x800000000000808an,0x8000000080008000n,0x000000000000808bn,0x0000000080000001n,0x8000000080008081n,0x8000000000008009n,0x000000000000008an,0x0000000000000088n,0x0000000080008009n,0x000000008000000an,0x000000008000808bn,0x800000000000008bn,0x8000000000008089n,0x8000000000008003n,0x8000000000008002n,0x8000000000000080n,0x000000000000800an,0x800000008000000an,0x8000000080008081n,0x8000000000008080n,0x0000000080000001n,0x8000000080008008n];

function ROL64(a,n){if(!n)return a;n=Number(n);const lo=Number(a&0xFFFFFFFFn),hi=Number((a>>32n)&0xFFFFFFFFn);let nl,nh;if(n<32){nl=((lo<<n)|(hi>>>(32-n)))>>>0;nh=((hi<<n)|(lo>>>(32-n)))>>>0}else{const m=n-32;nl=((hi<<m)|(lo>>>(32-m)))>>>0;nh=((lo<<m)|(hi>>>(32-m)))>>>0}return(BigInt(nl)|(BigInt(nh)<<32n))&0xFFFFFFFFFFFFFFFFn}
function KeccakF1600(st){const C=new BigInt64Array(5),B=new BigInt64Array(25);for(let r=0;r<24;r++){for(let x=0;x<5;x++)C[x]=st[x]^st[x+5]^st[x+10]^st[x+15]^st[x+20];for(let x=0;x<5;x++){const D=C[(x+4)%5]^ROL64(C[(x+1)%5],1);for(let y=0;y<5;y++)st[x+5*y]^=D}for(let i=0;i<25;i++)B[KeccakPiOffsets[i]]=ROL64(st[i],KeccakRhoOffsets[i]);for(let x=0;x<5;x++)for(let y=0;y<5;y++)st[x+5*y]=B[x+5*y]^((~B[(x+1)%5+5*y])&B[(x+2)%5+5*y]);st[0]^=KeccakRC[r]}}
function load64(b,i){let r=0n;for(let j=0;j<8;j++)r|=BigInt(b[i+j])<<BigInt(8*j);return r}
function store64(v){const b=new Uint8Array(8);let v2=v;for(let j=0;j<8;j++){b[j]=Number(v2&0xffn);v2>>=8n}return b}
function keccak(data,rate,outLen,suffix){const st=new BigInt64Array(25);const bs=rate>>3;const pl=Math.ceil((data.length+2)/bs)*bs;const p=new Uint8Array(pl);p.set(data);p[data.length]=suffix;p[pl-1]|=0x80;for(let o=0;o<pl;o+=bs){for(let j=0;j<bs;j+=8)st[j>>3]^=load64(p,o+j);KeccakF1600(st)}const out=new Uint8Array(outLen);let o=0;while(o<outLen){const t=Math.min(bs,outLen-o);for(let j=0;j<t;j+=8){const bytes=store64(st[j>>3]);for(let k=0;k<8&&o+k<outLen;k++)out[o+k]=bytes[k]}o+=t;if(o<outLen)KeccakF1600(st)}return out}
function sha3_256(d){return nobleSha3.sha3_256(d)} // hash backend: @noble/hashes
function sha3_512(d){return nobleSha3.sha3_512(d)} // hash backend: @noble/hashes
function shake128(d,len){return nobleSha3.shake128(d, { dkLen: len })} // hash backend: @noble/hashes
function shake256(d,len){return nobleSha3.shake256(d, { dkLen: len })} // hash backend: @noble/hashes

// ============================================================================
// byteEncode/Decode, compress/decompress, CBD, sampleNTT, poly ops
// ============================================================================
function byteEncode(f,d){const out=new Uint8Array(N*d>>>3);for(let i=0;i<N;i++){let t=((f[i]%Q)+Q)%Q;for(let j=0;j<d;j++){const bi=i*d+j;out[bi>>>3]|=((t>>>j)&1)<<(bi&7)}}return out}
function byteDecode(data,d){const f=new Int16Array(N);for(let i=0;i<N;i++){let t=0;for(let j=0;j<d;j++){const bi=i*d+j;t|=((data[bi>>>3]>>>(bi&7))&1)<<j}if(d===12&&t>=Q)t-=Q;f[i]=t}return f}
function compress(f,d){const g=new Int16Array(N);const rnd=3329>>1;for(let i=0;i<N;i++){const x=((f[i]%Q)+Q)%Q;g[i]=Number(((BigInt(x)*BigInt(1<<d)+BigInt(rnd))/BigInt(Q))&BigInt((1<<d)-1))}return g}
function decompress(g,d){const f=new Int16Array(N);for(let i=0;i<N;i++)f[i]=Number(((BigInt(g[i])*BigInt(Q)+BigInt(1<<(d-1)))>>BigInt(d)));return f}

// Centered Binomial Distribution (FIPS 203 Alg 8 SamplePolyCBD_eta).
// Samples 256 coefficients from 64*eta bytes of PRF output, little-endian bit order.
function cbd(buf, eta) {
    const r = new Int16Array(N);
    const n = 2 * eta;
    for (let i = 0; i < N; i++) {
        const base = n * i;
        let a = 0, b = 0;
        for (let j = 0; j < eta; j++) {
            const p1 = base + j;
            a += (buf[p1 >> 3] >> (p1 & 7)) & 1;
            const p2 = base + eta + j;
            b += (buf[p2 >> 3] >> (p2 & 7)) & 1;
        }
        r[i] = a - b;
    }
    return r;
}
function cbd2(buf) { return cbd(buf, 2); }

// Uniformly sample a polynomial in NTT domain.
// seed = ρ‖j‖i (34 bytes) → SHAKE-128(840) rejection sampling.
function sampleNTT(seed){const stream=shake128(seed,840);const a=new Int16Array(N);let j=0,off=0;while(j<N&&off+3<=stream.length){const d1=stream[off]|((stream[off+1]&0x0F)<<8),d2=(stream[off+1]>>4)|(stream[off+2]<<4);off+=3;if(d1<Q)a[j++]=d1;if(j<N&&d2<Q)a[j++]=d2}while(j<N)a[j++]=0;return a}

function polyMulNTT(a,b){const r=new Int16Array(N);for(let i=0;i<128;i++){let z=ZETAS[64+(i>>1)];if(i&1)z=modNeg(z);const a0=a[2*i],a1=a[2*i+1],b0=b[2*i],b1=b[2*i+1];r[2*i]=modAdd(modMul(modMul(a1,b1),z),modMul(a0,b0));r[2*i+1]=modAdd(modMul(a0,b1),modMul(a1,b0))}return r}
function polyAddNTT(a,b){const r=new Int16Array(N);for(let i=0;i<N;i++)r[i]=modAdd(a[i],b[i]);return r}
function vecDotNTT(a,b,k){let acc=new Int16Array(N);for(let i=0;i<k;i++)acc=polyAddNTT(acc,polyMulNTT(a[i],b[i]));return acc}
function matVecMulNTT(A,v,k){const r=[];for(let i=0;i<k;i++){let row=new Int16Array(N);for(let l=0;l<k;l++)row=polyAddNTT(row,polyMulNTT(A[i][l],v[l]));r[i]=row}return r}
function vecAddNTT(a,b,k){const r=[];for(let i=0;i<k;i++)r[i]=polyAddNTT(a[i],b[i]);return r}
function polyFromMsg(msg){const m=new Int16Array(N);for(let i=0;i<N;i++)m[i]=((msg[i>>>3]>>>(i&7))&1)*1665;return m}
function polyToMsg(f){const m=new Uint8Array(32);for(let i=0;i<N;i++){const x=((f[i]%Q)+Q)%Q;if(x>832&&x<2497)m[i>>>3]|=1<<(i&7)}return m}

// Back-compat wrapper for the legacy samplePoly(seed, nonce) signature
// (nonce = (i<<8)|j → seed‖j‖i, FIPS 203 double-byte packing).
function samplePolyCompat(seed, nonce) {
    const s = new Uint8Array(34);
    s.set(seed);
    s[32] = nonce & 0xFF;         // j
    s[33] = (nonce >> 8) & 0xFF;  // i
    return sampleNTT(s);
}

// ============================================================================
// KeyGen — FIPS 203 §7.1 (NTT domain, runtime parameter set)
// ============================================================================
function generateKeypair(){
    if (!_webcrypto) throw new Error('Web Crypto API (crypto.getRandomValues) required');
    const d=crypto.getRandomValues(new Uint8Array(32));
    const z=crypto.getRandomValues(new Uint8Array(32));
    return keygenDerand(d,z);
}

/**
 * Deterministic key generation — FIPS 203 Algorithm 16 with caller-supplied seeds.
 * Intended for KAT / ACVP vector testing only. Never pass attacker-controlled or
 * reused entropy: the point of the random wrapper above is that d and z are fresh.
 */
function keygenDerand(d,z){
    if(!(d instanceof Uint8Array)||d.length!==32) throw new Error('keygenDerand: d must be 32 bytes');
    if(!(z instanceof Uint8Array)||z.length!==32) throw new Error('keygenDerand: z must be 32 bytes');
    const K = KYBER_K, eta1 = _KYBER_ETA1;
    const H=sha3_512(new Uint8Array([...d,K])); // G(d‖k) — domain separator k
    const rho=H.slice(0,32), sigma=H.slice(32,64);

    // A[i][j] = sampleNTT(ρ‖j‖i) — FIPS Alg 13 step (already NTT domain)
    const A=[];
    for(let i=0;i<K;i++){
        A[i]=[];
        for(let j=0;j<K;j++){
            const seed=new Uint8Array(34);
            seed.set(rho);seed[32]=j;seed[33]=i;
            A[i][j]=sampleNTT(seed);
        }
    }

    // s[i] = ntt(CBD_eta1(PRF(σ,i))), e[i] = ntt(CBD_eta1(PRF(σ,i+k)))
    const s=[],e=[];
    for(let i=0;i<K;i++){
        s[i]=ntt(cbd(shake256(new Uint8Array([...sigma,i]),64*eta1),eta1));
        e[i]=ntt(cbd(shake256(new Uint8Array([...sigma,i+K]),64*eta1),eta1));
    }

    // t_hat[i] = A[i]*s_hat + e_hat — NTT domain, encoded directly into pk
    const As=matVecMulNTT(A,s,K);
    const t=As.map((row,i)=>polyAddNTT(row,e[i]));

    // pk = byteEncode₁₂(t_hat) || ρ
    const pk=new Uint8Array(KYBER_PUBLICKEYBYTES);
    let off=0;
    for(let i=0;i<K;i++){pk.set(byteEncode(t[i],12),off);off+=384;}
    pk.set(rho,off);

    // sk = byteEncode₁₂(s_hat) || pk || H(pk) || z  (s in NTT domain)
    const sk=new Uint8Array(KYBER_SECRETKEYBYTES);
    off=0;
    for(let i=0;i<K;i++){sk.set(byteEncode(s[i],12),off);off+=384;}
    sk.set(pk,off);off+=KYBER_PUBLICKEYBYTES;
    sk.set(sha3_256(pk),off);off+=32;
    sk.set(z,off);

    return {publicKey:pk,secretKey:sk};
}

// ============================================================================
// Encaps — FIPS 203 §7.2 (NTT domain)
// ============================================================================
function encapsulate(publicKey){
    if (!_webcrypto) throw new Error('Web Crypto API (crypto.getRandomValues) required');
    const m=crypto.getRandomValues(new Uint8Array(32));
    return encapsDerand(publicKey,m);
}

/**
 * Deterministic encapsulation — FIPS 203 Algorithm 17 with caller-supplied m.
 * For KAT / ACVP vector testing only; see the warning on keygenDerand.
 */
function encapsDerand(publicKey,m){
    if(!(m instanceof Uint8Array)||m.length!==32) throw new Error('encapsDerand: m must be 32 bytes');
    const K = KYBER_K, eta1 = _KYBER_ETA1, eta2 = _KYBER_ETA2;
    const duBytes = 32 * KYBER_DU;
    const rho=publicKey.slice(K*384,K*384+32);
    const hpk=sha3_256(publicKey);

    // G(m‖H(pk)) → SHA3-512 → (K_bar, r)
    const G=sha3_512(new Uint8Array([...m,...hpk]));
    const K_bar=G.slice(0,32), r=G.slice(32,64);

    // Â^T[i][j] = sampleNTT(ρ‖i‖j) — FIPS 203 §7.2 step 2
    const AT=[];
    for(let i=0;i<K;i++){
        AT[i]=[];
        for(let j=0;j<K;j++){
            const seed=new Uint8Array(34);
            seed.set(rho);seed[32]=i;seed[33]=j;
            AT[i][j]=sampleNTT(seed);
        }
    }

    // r_vec[i] = ntt(CBD_eta1(PRF(r,i))), e1[i] = ntt(CBD_eta2(PRF(r,i+K)))
    const rr=[],e1=[];
    for(let i=0;i<K;i++){
        rr[i]=ntt(cbd(shake256(new Uint8Array([...r,i]),64*eta1),eta1));
        e1[i]=ntt(cbd(shake256(new Uint8Array([...r,i+K]),64*eta2),eta2));
    }
    const e2=cbd(shake256(new Uint8Array([...r,2*K]),64*eta2),eta2);

    // u = iNTT(A^T * r_ntt) + iNTT(e1_ntt)
    const uprimeNTT=matVecMulNTT(AT,rr,K);
    const u=[];
    for(let i=0;i<K;i++){
        const ut=intt(new Int16Array(uprimeNTT[i]));
        const e1t=intt(new Int16Array(e1[i]));
        const ui=new Int16Array(N);
        for(let j=0;j<N;j++)ui[j]=modAdd(ut[j],e1t[j]);
        u[i]=ui;
    }

    // t_hat = byteDecode₁₂ from pk (NTT domain)
    const t_hat=[];
    let off=0;
    for(let i=0;i<K;i++){t_hat[i]=byteDecode(publicKey.slice(off,off+384),12);off+=384;}

    // v = iNTT(t_hat^T * r_ntt) + e2 + Decompress₁(m)
    const vprime=intt(vecDotNTT(t_hat,rr,K));
    const mu=polyFromMsg(m);
    const v=new Int16Array(N);
    for(let i=0;i<N;i++)v[i]=modAdd(modAdd(vprime[i],e2[i]),mu[i]);

    // ct = byteEncode_du(compress_du(u)) || byteEncode_dv(compress_dv(v))
    const ct=new Uint8Array(KYBER_CIPHERTEXTBYTES);
    off=0;
    for(let i=0;i<K;i++){ct.set(byteEncode(compress(u[i],KYBER_DU),KYBER_DU),off);off+=duBytes;}
    ct.set(byteEncode(compress(v,KYBER_DV),KYBER_DV),off);

    return {ciphertext:ct,sharedSecret:K_bar};  // return raw K_bar for noble compat
}

// ============================================================================
// Decaps — FIPS 203 §7.3 (NTT domain)
// ============================================================================
function decapsulate(secretKey,ciphertext){
    const K = KYBER_K, eta1 = _KYBER_ETA1, eta2 = _KYBER_ETA2;
    const duBytes = 32 * KYBER_DU;

    // sk = byteEncode₁₂(s_hat) || pk || H(pk) || z
    const s=[];
    let off=0;
    for(let i=0;i<K;i++){s[i]=byteDecode(secretKey.slice(off,off+384),12);off+=384;}
    const pk=secretKey.slice(off,off+KYBER_PUBLICKEYBYTES);off+=KYBER_PUBLICKEYBYTES;
    const _h=secretKey.slice(off,off+32);off+=32;  // H(pk) — implicit-rejection check field
    const z=secretKey.slice(off,off+32);

    // ct = … || compress_du(u) || compress_dv(v)
    const u=[];
    off=0;
    for(let i=0;i<K;i++){u[i]=decompress(byteDecode(ciphertext.slice(off,off+duBytes),KYBER_DU),KYBER_DU);off+=duBytes;}
    const v=decompress(byteDecode(ciphertext.slice(off,off+32*KYBER_DV),KYBER_DV),KYBER_DV);

    // u → NTT, s_hat · NTT(u) → iNTT = s·u
    const uNTT=u.map(ui=>ntt(new Int16Array(ui)));
    const su=intt(vecDotNTT(s,uNTT,K));

    // v - s·u → m'
    const mp=new Int16Array(N);
    for(let i=0;i<N;i++)mp[i]=modSub(v[i],su[i]);
    const mPrime=polyToMsg(mp);

    // G(m'‖H(pk)) → (K_bar', r')
    const hpk=sha3_256(pk);
    const G2=sha3_512(new Uint8Array([...mPrime,...hpk]));
    const K_bar_prime=G2.slice(0,32), r2seed=G2.slice(32,64);
    const rho=new Uint8Array(pk.slice(K*384,K*384+32));

    // Re-encrypt: Â^T[i][j] = sampleNTT(ρ‖i‖j)
    const AT=[];
    for(let i=0;i<K;i++){
        AT[i]=[];
        for(let j=0;j<K;j++){
            const seed=new Uint8Array(34);
            seed.set(rho);seed[32]=i;seed[33]=j;
            AT[i][j]=sampleNTT(seed);
        }
    }

    const r2=[],e1_2=[];
    for(let i=0;i<K;i++){
        r2[i]=ntt(cbd(shake256(new Uint8Array([...r2seed,i]),64*eta1),eta1));
        e1_2[i]=ntt(cbd(shake256(new Uint8Array([...r2seed,i+K]),64*eta2),eta2));
    }
    const e2_2=cbd(shake256(new Uint8Array([...r2seed,2*K]),64*eta2),eta2);

    const uprime2NTT=matVecMulNTT(AT,r2,K);
    const u2=[];
    for(let i=0;i<K;i++){
        const ut=intt(new Int16Array(uprime2NTT[i]));
        const e1t=intt(new Int16Array(e1_2[i]));
        const ui=new Int16Array(N);
        for(let j=0;j<N;j++)ui[j]=modAdd(ut[j],e1t[j]);
        u2[i]=ui;
    }

    const t_hat2=[];
    let toff=0;
    for(let i=0;i<K;i++){t_hat2[i]=byteDecode(pk.slice(toff,toff+384),12);toff+=384;}
    const v2prime=intt(vecDotNTT(t_hat2,r2,K));
    const mu2=polyFromMsg(mPrime);
    const v2=new Int16Array(N);
    for(let i=0;i<N;i++)v2[i]=modAdd(modAdd(v2prime[i],e2_2[i]),mu2[i]);

    const ct2=new Uint8Array(KYBER_CIPHERTEXTBYTES);
    off=0;
    for(let i=0;i<K;i++){ct2.set(byteEncode(compress(u2[i],KYBER_DU),KYBER_DU),off);off+=duBytes;}
    ct2.set(byteEncode(compress(v2,KYBER_DV),KYBER_DV),off);

    // Constant-time FO implicit-rejection selection (FIPS 203 §7.3 step 8-10)
    const eqMask = ctEqMask(ciphertext, ct2);
    const K_ok = K_bar_prime;                       // matches → return K̂'
    const K_rej = shake256(new Uint8Array([...z,...ciphertext]),32);  // J(z‖c)
    const sharedSecret = ctSelectU8(K_ok, K_rej, eqMask);

    zeroizeU8(K_ok); zeroizeU8(K_rej);
    return sharedSecret;
}

// ============================================================================
// Key checks — FIPS 203 §7.2 (encapsulation key) / §7.3 (decapsulation key)
// ============================================================================

/**
 * Encapsulation key check — FIPS 203 §7.2.
 * Two conditions: length matches the active parameter set, and the 12-bit encoded
 * t̂ is canonical (byteEncode12 ∘ byteDecode12 is the identity). Values ≥ q survive
 * decoding but not re-encoding, which is exactly what the modulus check catches.
 * Returns a boolean; the ACVP keyCheck groups expect nothing else.
 */
function encapsKeyCheck(ek){
    if(!(ek instanceof Uint8Array)) return false;
    if(ek.length!==KYBER_PUBLICKEYBYTES) return false;
    const K=KYBER_K;
    for(let i=0;i<K;i++){
        const slice=ek.subarray(i*384,(i+1)*384);
        const reenc=byteEncode(byteDecode(slice,12),12);
        for(let j=0;j<reenc.length;j++) if(reenc[j]!==slice[j]) return false;
    }
    return true;
}

/**
 * Decapsulation key check — FIPS 203 §7.3.
 * Two conditions: length matches the active parameter set, and the stored H(ek)
 * agrees with a fresh hash of the embedded ek. The embedded ek is deliberately
 * not modulus-checked: FIPS 203 does not require it here, and ACVP marks keys as
 * valid when only the hash agrees.
 */
function decapsKeyCheck(dk){
    if(!(dk instanceof Uint8Array)) return false;
    if(dk.length!==KYBER_SECRETKEYBYTES) return false;
    const K=KYBER_K;
    const ekOff=K*384;
    const ek=dk.subarray(ekOff,ekOff+KYBER_PUBLICKEYBYTES);
    const stored=dk.subarray(ekOff+KYBER_PUBLICKEYBYTES,ekOff+KYBER_PUBLICKEYBYTES+32);
    const fresh=sha3_256(ek);
    for(let i=0;i<32;i++) if(stored[i]!==fresh[i]) return false;
    return true;
}

// ============================================================================
// Module export
// ============================================================================
const MLKEM768 = {
    generateKeypair,encapsulate,decapsulate,
    // Deterministic variants — KAT/ACVP only (see keygenDerand doc comment)
    generateKeypairDerand: keygenDerand, encapsulateDerand: encapsDerand,
    // Input validation — FIPS 203 §7.2 / §7.3
    encapsKeyCheck, decapsKeyCheck,
    get PUBLIC_KEY_BYTES() { return KYBER_PUBLICKEYBYTES; },
    get SECRET_KEY_BYTES() { return KYBER_SECRETKEYBYTES; },
    get CIPHERTEXT_BYTES() { return KYBER_CIPHERTEXTBYTES; },
    get SHARED_SECRET_BYTES() { return KYBER_SSBYTES; },
    // NTT core helpers
    ntt,intt,NTT:ntt,iNTT:intt,
    polyMulNTT,polyAddNTT,vecDotNTT,matVecMulNTT,vecAddNTT,
    compress,decompress,byteEncode,byteDecode,
    modAdd,modSub,modMul,modNeg,sampleNTT,cbd,cbd2,
    polyFromMsg,polyToMsg,
    sha3_256,sha3_512,shake128,shake256,
    ZETAS,
    // Constant-time helpers (audit/tvla)
    ctSelectU8,ctEqMask,zeroizeU8,zeroizeI16,zeroizePolyVec,
    // Algorithm agility — runtime parameter switching
    get currentParamSet() { return _currentParamSet; },
    loadParams,listParamSets,getParams,MLKEM_PARAMS,
    // Back-compat aliases (legacy time-domain names → NTT semantics)
    polyMul:polyMulNTT,
    vecDot:vecDotNTT,
    matVecMul:matVecMulNTT,
    vecAdd:vecAddNTT,
    samplePoly:samplePolyCompat,
};

if(typeof module!=='undefined'&&module.exports)module.exports=MLKEM768;
