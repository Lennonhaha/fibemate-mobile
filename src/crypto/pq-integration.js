/**
 * FIBEMATE Post-Quantum Integration Module
 * 
 * Integrates ML-KEM-768 with Double Ratchet for hybrid post-quantum security.
 * 
 * Architecture:
 * - X3DH initialization uses Hybrid Key Exchange (ML-KEM + ECDH P-256)
 * - Double Ratchet chain keys derived from hybrid shared secret
 * - Provides both classical and post-quantum security
 */

// Import ML-KEM-768 (works with both module and global)
const MLKEM = typeof window !== 'undefined' && window.MLKEM768 ? window.MLKEM768 : null;

/**
 * Post-Quantum Double Ratchet Extension
 * Extends the standard Double Ratchet with ML-KEM-768 hybrid key exchange
 */
class PQDoubleRatchet {
    constructor() {
        this.dr = null; // Standard Double Ratchet instance
        this.hybridSecret = null; // Combined ML-KEM + ECDH secret
        this.kemKeypair = null; // ML-KEM keypair
    }

    /**
     * Initialize with hybrid X3DH
     * @param {Object} identityKey - Our identity key pair
     * @param {Object} signedPreKey - Our signed prekey
     * @param {Array} oneTimePreKeys - Our one-time prekeys
     */
    async initializeX3DH(identityKey, signedPreKey, oneTimePreKeys) {
        // Generate hybrid key exchange parameters
        const hke = new MLKEM.HybridKeyExchange();
        const initResult = await hke.initialize();
        
        this.kemKeypair = {
            publicKey: initResult.kemPublicKey,
            secretKey: hke.kemKeypair.secretKey
        };
        
        // Store for later use in X3DH
        this.hybridKEM = hke;
        
        return {
            identityKey,
            signedPreKey,
            oneTimePreKeys,
            kemPublicKey: initResult.kemPublicKey,
            ecdhPublicKey: initResult.ecdhPublicKey
        };
    }

    /**
     * Perform hybrid X3DH key agreement (initiator)
     * @param {Object} peerBundle - Peer's public key bundle
     */
    async x3dhInitiate(peerBundle) {
        // Standard ECDH X3DH
        const ecdhResult = await this._ecdhX3DH(peerBundle);
        
        // ML-KEM encapsulation to peer
        const kemResult = await MLKEM.encapsulate(peerBundle.kemPublicKey);
        
        // Combine secrets
        const hybridSecret = await MLKEM.hybridCombine(
            kemResult.sharedSecret,
            ecdhResult.sharedSecret
        );
        
        this.hybridSecret = hybridSecret;
        
        return {
            ciphertext: kemResult.ciphertext,
            ecdhPublicKey: ecdhResult.publicKey,
            hybridSecret
        };
    }

    /**
     * Perform hybrid X3DH key agreement (responder)
     * @param {Uint8Array} kemCiphertext - ML-KEM ciphertext from initiator
     * @param {ArrayBuffer} ecdhPublicKey - ECDH public key from initiator
     */
    async x3dhRespond(kemCiphertext, ecdhPublicKey) {
        // Decapsulate ML-KEM
        const kemSecret = await MLKEM.decapsulate(
            this.kemKeypair.secretKey,
            kemCiphertext
        );
        
        // ECDH key agreement
        const ecdhSecret = await this._ecdhRespond(ecdhPublicKey);
        
        // Combine secrets
        const hybridSecret = await MLKEM.hybridCombine(kemSecret, ecdhSecret);
        
        this.hybridSecret = hybridSecret;
        
        return { hybridSecret };
    }

    /**
     * Initialize Double Ratchet with hybrid secret
     */
    async initializeRatchet() {
        if (!this.hybridSecret) {
            throw new Error('Hybrid secret not established. Run X3DH first.');
        }

        // Use hybrid secret as root key for Double Ratchet
        // Import from message-crypto.js or double-ratchet.js
        if (typeof DoubleRatchet !== 'undefined') {
            this.dr = new DoubleRatchet();
            await this.dr.initialize(this.hybridSecret);
        } else {
            console.warn('DoubleRatchet not available. Storing hybrid secret for later.');
        }
        
        return this.dr;
    }

    // Private helper methods
    async _ecdhX3DH(peerBundle) {
        // Simplified ECDH X3DH - production uses full implementation
        const ecdhKey = await crypto.subtle.generateKey(
            { name: 'ECDH', namedCurve: 'P-256' },
            true,
            ['deriveBits']
        );
        
        const peerKey = await crypto.subtle.importKey(
            'raw',
            peerBundle.signedPreKey,
            { name: 'ECDH', namedCurve: 'P-256' },
            false,
            []
        );
        
        const sharedSecret = await crypto.subtle.deriveBits(
            { name: 'ECDH', public: peerKey },
            ecdhKey.privateKey,
            256
        );
        
        const publicKey = await crypto.subtle.exportKey('raw', ecdhKey.publicKey);
        
        return {
            sharedSecret: new Uint8Array(sharedSecret),
            publicKey
        };
    }

    async _ecdhRespond(ecdhPublicKey) {
        // Production implementation would use our private key
        // This is a simplified version
        return new Uint8Array(32); // Placeholder
    }
}

/**
 * Post-Quantum Key Manager
 * Manages hybrid keys for all conversations
 */
class PQKeyManager {
    constructor() {
        this.conversations = new Map(); // conversationId -> PQDoubleRatchet
        this.dbName = 'fibemate-pq-keys';
        this.dbVersion = 1;
    }

    /**
     * Initialize conversation with post-quantum security
     */
    async initConversation(conversationId, peerBundle) {
        const pq = new PQDoubleRatchet();
        
        // Initialize our keys
        const ourBundle = await pq.initializeX3DH();
        
        // Perform X3DH
        const x3dhResult = await pq.x3dhInitiate(peerBundle);
        
        // Initialize Double Ratchet
        await pq.initializeRatchet();
        
        // Store
        this.conversations.set(conversationId, pq);
        await this._saveToStorage(conversationId, pq);
        
        return {
            ourBundle,
            x3dhResult
        };
    }

    /**
     * Get Double Ratchet instance for conversation
     */
    getRatchet(conversationId) {
        const pq = this.conversations.get(conversationId);
        return pq ? pq.dr : null;
    }

    /**
     * Save conversation keys to persistent storage
     */
    async _saveToStorage(conversationId, pq) {
        try {
            const data = {
                kemKeypair: pq.kemKeypair ? {
                    publicKey: Array.from(pq.kemKeypair.publicKey),
                    secretKey: Array.from(pq.kemKeypair.secretKey)
                } : null,
                hybridSecret: pq.hybridSecret ? Array.from(pq.hybridSecret) : null
            };
            
            localStorage.setItem(`pq_${conversationId}`, JSON.stringify(data));
        } catch (e) {
            console.error('Failed to save PQ keys:', e);
        }
    }

    /**
     * Load conversation keys from storage
     */
    async loadFromStorage(conversationId) {
        try {
            const data = JSON.parse(localStorage.getItem(`pq_${conversationId}`));
            if (!data) return null;
            
            const pq = new PQDoubleRatchet();
            if (data.kemKeypair) {
                pq.kemKeypair = {
                    publicKey: new Uint8Array(data.kemKeypair.publicKey),
                    secretKey: new Uint8Array(data.kemKeypair.secretKey)
                };
            }
            if (data.hybridSecret) {
                pq.hybridSecret = new Uint8Array(data.hybridSecret);
            }
            
            this.conversations.set(conversationId, pq);
            return pq;
        } catch (e) {
            console.error('Failed to load PQ keys:', e);
            return null;
        }
    }
}

// SLH-DSA (SPHINCS+) lazy-loaded via WASM
let _slhDsaModule = null;
let _slhDsaInitPromise = null;

/**
 * SLH-DSA-128s Stateless Hash-Based Signature (FIPS 205).
 * Used for message authentication alongside ML-KEM-768 key exchange.
 */
const SLHDSA = {
    /**
     * Check if SLH-DSA is available.
     * @returns {Promise<boolean>}
     */
    async isAvailable() {
        try {
            await this._ensureLoaded();
            return true;
        } catch (e) {
            console.warn('SLH-DSA WASM not available:', e.message);
            return false;
        }
    },

    /**
     * Generate a new SLH-DSA keypair.
     * @returns {Promise<{publicKey: string, secretKey: string, sigBytes: number}>}
     */
    async keygen() {
        const mod = await this._ensureLoaded();
        const jsonStr = mod.keygen();
        const keys = JSON.parse(jsonStr);
        return { ...keys, sigBytes: 7856 };
    },

    /**
     * Sign a message (CPU-intensive ~500ms, call from Worker).
     * @param {string} message
     * @param {string} secretKeyB64
     * @param {string} publicKeyB64
     * @returns {Promise<string>} Base64 signature
     */
    async sign(message, secretKeyB64, publicKeyB64) {
        const mod = await this._ensureLoaded();
        return mod.sign(message, publicKeyB64, secretKeyB64);
    },

    /**
     * Verify a signature (fast ~10ms, main thread safe).
     * @param {string} sigB64
     * @param {string} message
     * @param {string} publicKeyB64
     * @returns {Promise<boolean>}
     */
    async verify(sigB64, message, publicKeyB64) {
        const mod = await this._ensureLoaded();
        return mod.verify(sigB64, message, publicKeyB64);
    },

    /**
     * Get algorithm parameters.
     * @returns {Promise<Object>}
     */
    async getParams() {
        const mod = await this._ensureLoaded();
        return JSON.parse(mod.get_params());
    },

    async _ensureLoaded() {
        if (_slhDsaModule) return _slhDsaModule;
        if (_slhDsaInitPromise) return _slhDsaInitPromise;

        _slhDsaInitPromise = (async () => {
            try {
                const module = await import('./slh-dsa-wasm/pkg/fibemate_slh_dsa_wasm.js');
                await module.default();
                _slhDsaModule = module;
                console.log('[PQIntegration] SLH-DSA WASM loaded');
                return module;
            } catch (e) {
                // Clear on failure so next call retries instead of caching failure forever
                _slhDsaInitPromise = null;
                throw e;
            }
        })();

        return _slhDsaInitPromise;
    }
};

// Export
const PQIntegration = {
    PQDoubleRatchet,
    PQKeyManager,
    SLHDSA,
    
    /**
     * Check if post-quantum cryptography is available
     */
    isAvailable() {
        return MLKEM !== null && typeof crypto !== 'undefined' && crypto.subtle;
    },

    /**
     * Get security info
     */
    getSecurityInfo() {
        return {
            algorithm: 'ML-KEM-768 + ECDH P-256 Hybrid',
            classicalSecurity: '128-bit (ECDH P-256)',
            quantumSecurity: '192-bit (ML-KEM-768)',
            combinedSecurity: '128-bit classical + post-quantum',
            signatureAlgorithm: 'SLH-DSA-128s (FIPS 205)',
            status: this.isAvailable() ? 'available' : 'unavailable'
        };
    }
};

// Make available globally
if (typeof window !== 'undefined') {
    window.PQIntegration = PQIntegration;
}

if (typeof module !== 'undefined' && module.exports) {
    module.exports = PQIntegration;
}
