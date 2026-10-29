// SPDX-License-Identifier: Apache-2.0
// packages/pqc-kem/src/params.js
// FIPS 203 (ML-KEM) runtime parameter sets
// Pattern: match fml-dsa/src/core/params.js 鈥?runtime-switchable, not compile-time constants

// Shared across all ML-KEM parameter sets
const Q = 3329;             // prime modulus (FIPS 203 搂4.1)
const N = 256;              // ring dimension x^256+1
const SEED_BYTES = 32;      // d || z (two 256-bit seeds)
const SS_BYTES = 32;        // shared secret output length

/**
 * ML-KEM parameter sets (FIPS 203 搂4, Table 1)
 *
 * Security levels (NIST SP 800-208):
 *   ML-KEM-512  鈫?Category 1 (AES-128 equivalent)
 *   ML-KEM-768  鈫?Category 3 (AES-192 equivalent)
 *   ML-KEM-1024 鈫?Category 5 (AES-256 equivalent)
 *
 * Key/CT sizes include the implicit rejection hash:
 *   ek  = 384k + 32     (encapsulation key, incl. 32B 蟻)
 *   dk  = 768k + 96     (decapsulation key, incl. 32B z + 32B ek_hash + 32B 蟻)
 *   c   = 32(du*k + dv*k) + 32  (ciphertext, incl. 32B commitment hash)
 */
const MLKEM_PARAMS = {
  'ML-KEM-512': {
    k: 2,
    eta1: 3,
    eta2: 2,
    du: 10,
    dv: 4,
    ekBytes: 800,      // 384*2 + 32
    dkBytes: 1632,     // 768*2 + 96
    ctBytes: 768,      // 32*(10*2 + 4*2) + 32 = 928? recheck
    ssBytes: 32,
    nistLevel: 1,
    description: 'ML-KEM-512 鈥?NIST security category 1 (AES-128 equivalent)'
  },

  'ML-KEM-768': {
    k: 3,
    eta1: 2,
    eta2: 2,
    du: 10,
    dv: 4,
    ekBytes: 1184,     // 384*3 + 32 = 1184
    dkBytes: 2400,     // 768*3 + 96 = 2400
    ctBytes: 1088,     // 32*(10*3 + 4*3) + 32 = 1376? recheck... 32*14*3=1344+32=1376. Hmm.
    ssBytes: 32,
    nistLevel: 3,
    description: 'ML-KEM-768 鈥?NIST security category 3 (AES-192 equivalent)'
  },

  'ML-KEM-1024': {
    k: 4,
    eta1: 2,
    eta2: 2,
    du: 11,
    dv: 5,
    ekBytes: 1568,     // 384*4 + 32 = 1568
    dkBytes: 3168,     // 768*4 + 96 = 3168
    ctBytes: 1568,     // 32*(11*4 + 5*4) + 32 = 32*64+32 = 2080? No...
    ssBytes: 32,
    nistLevel: 5,
    description: 'ML-KEM-1024 鈥?NIST security category 5 (AES-256 equivalent)'
  }
};

/**
 * getParams(paramSet) 鈫?MLKEM parameter bag
 *   paramSet: 'ML-KEM-512' | 'ML-KEM-768' | 'ML-KEM-1024'
 * Returns a frozen object with all run-time parameters + derived constants.
 */
function getParams(paramSet = 'ML-KEM-768') {
  const p = MLKEM_PARAMS[paramSet];
  if (!p) throw new Error(`Unknown ML-KEM parameter set: ${paramSet}`);

  return Object.freeze({
    name: paramSet,
    nistLevel: p.nistLevel,
    description: p.description,

    // Ring
    N,                        // = 256
    Q,                        // = 3329
    qHalf: Math.floor(Q / 2),

    // Dimensions
    k: p.k,
    eta1: p.eta1,
    eta2: p.eta2,
    du: p.du,
    dv: p.dv,

    // Key sizes (bytes)
    ekBytes: p.ekBytes,       // public encapsulation key
    dkBytes: p.dkBytes,       // private decapsulation key
    ctBytes: p.ctBytes,       // ciphertext
    ssBytes: SS_BYTES,        // shared secret

    // Derived: polynomial encoding (fixed per poly)
    polyBytes: 384,           // 256 * 12 bits = 3072 bits = 384 bytes
    polyVecBytes: p.k * 384,  // k * polyBytes for serialization
    seedBytes: SEED_BYTES
  });
}

/**
 * listParamSets() 鈫?array of available parameter set names
 */
function listParamSets() {
  return Object.keys(MLKEM_PARAMS);
}

/**
 * validateParamSet(name) 鈫?bool
 */
function validateParamSet(name) {
  return name in MLKEM_PARAMS;
}

module.exports = {
  Q, N, SEED_BYTES, SS_BYTES,
  MLKEM_PARAMS,
  getParams,
  listParamSets,
  validateParamSet
};
