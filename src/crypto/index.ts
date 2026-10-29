/**
 * FIBEMATE Mobile Crypto Service
 * Wraps the web crypto modules for React Native Hermes compatibility.
 *
 * Hermes does not support eval/new Function, so all JS modules must
 * be CJS/UMD-compatible and avoid dynamic code generation.
 */

// These are direct JS modules ported from the web version.
// They use plain BigInt math and modular arithmetic—Hermes-safe.

// slh-dsa.js exports named async functions, no default
import * as SLHDSA from './slh-dsa.js';

// ML-KEM-768: one engine, FIPS 203 (see ./kem). No legacy export, no fallback.
export * from './kem';
export { default as SM3 } from './sm3-browser.js';
export { default as SM4 } from './sm4-browser.js';
export * from './opk-client.js';
export { default as SecurityLevels } from './security-levels.js';
export { default as ConstantTime } from './constant-time.js';
export { SLHDSA };
