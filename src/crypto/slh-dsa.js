/**
 * SLH-DSA-128s (SPHINCS+) Frontend Wrapper
 *
 * Bridges the WASM module to JavaScript. Follows the same pattern as ml-kem-768.js.
 *
 * Architecture:
 *   sign()   → Web Worker  (~500ms, async, non-blocking)
 *   verify() → Main thread   (~10ms, sync)
 *   keygen() → Main thread   (~50ms, sync, one-shot per identity)
 *
 * Parameters (SLH-DSA-SHA2-128s):
 *   Public key:  32 bytes
 *   Secret key:  64 bytes
 *   Signature:   7,856 bytes (7.8 KB)
 *   Security:    NIST Level 1 (128-bit classical, ~64-bit quantum)
 */

/**
 * @typedef {Object} SlhDsaKeys
 * @property {string} publicKey  - Base64-encoded 32-byte public key
 * @property {string} secretKey  - Base64-encoded 64-byte secret key
 * @property {number} sigBytes   - Signature size in bytes (7,856)
 */

// ================================================
// WASM Module Loading (lazy)
// ================================================

/** @type {Object|null} */
let wasmModule = null;

/** @type {Promise<void>|null} */
let initPromise = null;

/**
 * Load the SLH-DSA WASM module.
 * Called automatically on first use; can be pre-loaded via `preload()`.
 *
 * Uses relative import from slh-dsa-wasm/pkg/ for Tauri/Vite compatibility.
 * For production CDN deployment, pass a custom path.
 *
 * @param {string} [wasmPath] - Custom WASM path (defaults to relative import)
 * @returns {Promise<void>}
 */
export async function preload(wasmPath) {
    if (wasmModule) return;
    if (initPromise) return initPromise;

    initPromise = (async () => {
        try {
            if (wasmPath) {
                // CDN / custom path
                const module = await import(/* webpackIgnore: true */ wasmPath);
                await module.default();
                wasmModule = module;
            } else {
                // Tauri/Vite: relative import (bundler resolves the path)
                const module = await import('./slh-dsa-wasm/pkg/fibemate_slh_dsa_wasm.js');
                await module.default();
                wasmModule = module;
            }
        } catch (e) {
            // Clear cached promise on failure so next call retries
            initPromise = null;
            throw e;
        }
    })();

    return initPromise;
}

/**
 * Ensure WASM is loaded (call before any operation).
 * @returns {Promise<Object>} The WASM module exports
 */
async function ensureWasm() {
    await preload();
    return wasmModule;
}

// ================================================
// Key Generation
// ================================================

/**
 * Generate a new SLH-DSA-128s keypair.
 *
 * @returns {Promise<SlhDsaKeys>} { publicKey, secretKey, sigBytes }
 */
export async function keygen() {
    const mod = await ensureWasm();
    const jsonStr = mod.keygen();
    const keys = JSON.parse(jsonStr);
    return {
        ...keys,
        sigBytes: 7856,
    };
}

// ================================================
// Sign
// ================================================

/**
 * Sign a message using SLH-DSA-128s.
 *
 * ⚠️ CPU-intensive (~500ms). Use from a Web Worker.
 *
 * @param {string} message - Message to sign (UTF-8)
 * @param {string} secretKey - Base64-encoded 64-byte secret key
 * @param {string} publicKey - Base64-encoded 32-byte public key
 * @returns {Promise<string>} Base64-encoded signature (~10,476 chars)
 */
export async function sign(message, secretKey, publicKey) {
    const mod = await ensureWasm();
    return mod.sign(message, publicKey, secretKey);
}

// ================================================
// Verify
// ================================================

/**
 * Verify a SLH-DSA-128s signature.
 *
 * Fast (~10ms) — safe for main thread.
 *
 * @param {string} signatureB64 - Base64-encoded signature
 * @param {string} message - Original message (UTF-8)
 * @param {string} publicKey - Base64-encoded 32-byte public key
 * @returns {Promise<boolean>} true if valid
 */
export async function verify(signatureB64, message, publicKey) {
    const mod = await ensureWasm();
    return mod.verify(signatureB64, message, publicKey);
}

// ================================================
// Algorithm Info
// ================================================

/**
 * Get algorithm parameters.
 * @returns {Promise<Object>}
 */
export async function getParams() {
    const mod = await ensureWasm();
    return JSON.parse(mod.get_params());
}

// ================================================
// Feature Detection
// ================================================

let _available = null;

/**
 * Check if SLH-DSA WASM is available in this environment.
 * @returns {Promise<boolean>}
 */
export async function isAvailable() {
    if (_available === true) return true;
    try {
        await preload();
        _available = true;
        return true;
    } catch (e) {
        console.warn('SLH-DSA WASM not available (will retry):', e.message);
        // Don't cache failure — retry on next call
        _available = null;
        return false;
    }
}

// ================================================
// Web Worker Interface
// ================================================

/**
 * Create a Web Worker for async signing (non-blocking).
 *
 * Usage:
 * ```js
 * import { createSignWorker } from './slh-dsa.js';
 * const worker = createSignWorker();
 * worker.sign(message, secretKey, publicKey).then(sig => ...);
 * ```
 *
 * @param {string} [workerScriptPath] - Path to slh-dsa.worker.js
 * @returns {{ sign: Function, terminate: Function }}
 */
export function createSignWorker(workerScriptPath = 'crypto/slh-dsa.worker.js') {
    const worker = new Worker(workerScriptPath, { type: 'module' });
    const pending = new Map();
    let idCounter = 0;

    worker.onmessage = (e) => {
        const { id, result, error } = e.data;
        const { resolve, reject } = pending.get(id) || {};
        pending.delete(id);
        if (error) {
            reject(new Error(error));
        } else {
            resolve(result);
        }
    };

    return {
        /**
         * Sign a message in a Web Worker.
         * @param {string} message
         * @param {string} secretKey
         * @param {string} publicKey
         * @returns {Promise<string>} Base64 signature
         */
        sign(message, secretKey, publicKey) {
            return new Promise((resolve, reject) => {
                const id = ++idCounter;
                pending.set(id, { resolve, reject });
                worker.postMessage({ id, type: 'sign', message, secretKey, publicKey });
            });
        },

        terminate() {
            worker.terminate();
            pending.clear();
        },
    };
}

// ================================================
// Global Bridge (for non-module consumers)
// ================================================
// ESM modules CAN set window globals — this provides
// a zero-friction upgrade path for existing <script> tags
// that reference window.SLHDSA.
if (typeof window !== 'undefined') {
    window.SLHDSA = {
        keygen,
        sign,
        verify,
        isAvailable,
        preload,
        getParams,
        createSignWorker,
    };
}
