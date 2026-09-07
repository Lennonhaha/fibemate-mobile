/**
 * FIBEMATE Mobile Crypto Service
 * Wraps the web crypto modules for React Native Hermes compatibility.
 *
 * Hermes does not support eval/new Function, so all JS modules must
 * be CJS/UMD-compatible and avoid dynamic code generation.
 */

// These are direct JS modules ported from the web version.
// They use plain BigInt math and modular arithmetic—Hermes-safe.

// gm.js exports: module.exports = MessageGM (CJS default)
import MessageGM from './gm.js';

// slh-dsa.js exports named async functions, no default
import * as SLHDSA from './slh-dsa.js';

export { default as MLKEM768 } from './ml-kem-768.js';
export { default as SM2 } from './sm2-browser.js';
export { default as SM3 } from './sm3-browser.js';
export { default as SM4 } from './sm4-browser.js';
export * from './opk-client.js';
export { default as PQCIntegration } from './pq-integration.js';
export { default as PqcHybridClient } from './pqc-hybrid-client.js';
export { default as SecurityLevels } from './security-levels.js';
export { default as ConstantTime } from './constant-time.js';
export { MessageGM, SLHDSA };
