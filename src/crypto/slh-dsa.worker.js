/**
 * SLH-DSA Signing Web Worker
 *
 * Offloads CPU-intensive SPHINCS+ signing (~500ms) off the main thread.
 *
 * Deployment: Copy to public/wasm/slh-dsa/slh-dsa.worker.js
 * The worker imports the main slh-dsa.js module from the same directory.
 *
 * In Vite, use `new Worker(new URL('./slh-dsa.worker.js', import.meta.url), { type: 'module' })`.
 * For simpler setups, use the `createSignWorker()` factory in slh-dsa.js.
 */

// Worker context: import the WASM module and handle sign requests
// Tauri/Vite: relative import from same directory
import { preload, sign } from './slh-dsa.js';

let ready = false;

// Preload WASM on worker start
preload().then(() => {
    ready = true;
    self.postMessage({ type: 'ready' });
}).catch(err => {
    self.postMessage({ type: 'error', error: `WASM load failed: ${err.message}` });
});

self.onmessage = async (e) => {
    const { id, type, message, secretKey, publicKey } = e.data;

    if (type === 'sign') {
        if (!ready) {
            self.postMessage({ id, error: 'Worker not ready' });
            return;
        }
        try {
            const sig = await sign(message, secretKey, publicKey);
            self.postMessage({ id, result: sig });
        } catch (err) {
            self.postMessage({ id, error: err.message });
        }
    }
};
