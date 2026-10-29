/**
 * ML-KEM-768 engine boundary (FIPS 203).
 *
 * Plain CJS so `node --test` can exercise the exact code the app runs (the repo's
 * other crypto modules use the same pattern). Typed surface lives in `./index.ts`.
 *
 * Clean-break policy: exactly one implementation. There is no registry, no version
 * negotiation and no fallback — a second reachable engine is a downgrade path waiting
 * to be used. Legacy material fails loudly with `LegacyKemMaterialError`.
 */

'use strict';

const MLKEM = require('./vendor/ml-kem-768.js');

const KEM_ALGORITHM = 'ML-KEM-768';
const KEM_VERSION = 'v2_fips';

class KemError extends Error {
  constructor(code, message) {
    super(message);
    this.name = new.target.name;
    this.code = code;
  }
}

class InvalidEncapsulationKeyError extends KemError {
  constructor(message) {
    super('invalid_encapsulation_key', message);
  }
}

class InvalidDecapsulationKeyError extends KemError {
  constructor(message) {
    super('invalid_decapsulation_key', message);
  }
}

class InvalidCiphertextError extends KemError {
  constructor(message) {
    super('invalid_ciphertext', message);
  }
}

/**
 * Raised when material produced by the retired pure-JS engine is encountered.
 *
 * The check is functional, not structural: the legacy public key and the legacy secret
 * key both pass FIPS 203's encoding checks (§7.2 / §7.3), because both encodings are
 * 12-bit canonical. Only an encapsulate/decapsulate loop over the key distinguishes
 * them — which is why this class carries a `source` and not a key fingerprint.
 */
class LegacyKemMaterialError extends KemError {
  constructor(source, message) {
    super('legacy_kem_material', message);
    this.source = source;
  }
}

const KEM_SIZES = {
  publicKey: MLKEM.PUBLIC_KEY_BYTES,
  secretKey: MLKEM.SECRET_KEY_BYTES,
  ciphertext: MLKEM.CIPHERTEXT_BYTES,
  sharedSecret: MLKEM.SHARED_SECRET_BYTES,
};

// Deterministic probe message. Not secret; used only by isFipsCapable.
const PROBE_MESSAGE = new Uint8Array(32);

function equalBytes(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i += 1) diff |= a[i] ^ b[i];
  return diff === 0;
}

/**
 * True when `secretKey` is a working FIPS 203 decapsulation key.
 * Runs one encapsulate/decapsulate round trip against the key's own embedded public key.
 */
function isFipsCapable(secretKey) {
  if (!MLKEM.decapsKeyCheck(secretKey)) return false;
  try {
    // sk = encode12(s_hat) || ek || H(ek) || z. ek starts after the s_hat block, not at
    // `publicKey.length` (1152 vs 1184 for ML-KEM-768).
    const publicKeyOffset = KEM_SIZES.secretKey - KEM_SIZES.publicKey - 64;
    const embeddedPublicKey = secretKey.subarray(publicKeyOffset, publicKeyOffset + KEM_SIZES.publicKey);
    const probe = MLKEM.encapsulateDerand(embeddedPublicKey, PROBE_MESSAGE);
    const opened = MLKEM.decapsulate(secretKey, probe.ciphertext);
    return equalBytes(opened, probe.sharedSecret);
  } catch {
    return false;
  }
}

const kem = {
  algorithm: KEM_ALGORITHM,
  version: KEM_VERSION,
  sizes: KEM_SIZES,

  generateKeypair() {
    return MLKEM.generateKeypair();
  },

  /** KAT/ACVP only: FIPS 203 KeyGen_internal(d, z). Never pass reused entropy. */
  deriveKeypair(d, z) {
    return MLKEM.generateKeypairDerand(d, z);
  },

  isValidEncapsulationKey(publicKey) {
    return MLKEM.encapsKeyCheck(publicKey);
  },

  assertValidEncapsulationKey(publicKey) {
    if (!MLKEM.encapsKeyCheck(publicKey)) {
      throw new InvalidEncapsulationKeyError(
        `encapsulation key failed FIPS 203 §7.2 checks (length ${publicKey && publicKey.length})`,
      );
    }
  },

  assertFipsCapable(secretKey, source) {
    if (!MLKEM.decapsKeyCheck(secretKey)) {
      throw new InvalidDecapsulationKeyError(
        `decapsulation key failed FIPS 203 §7.3 checks (length ${secretKey && secretKey.length})`,
      );
    }
    if (!isFipsCapable(secretKey)) {
      throw new LegacyKemMaterialError(
        source || 'secret_key',
        'key passes FIPS 203 encoding checks but fails a self-generated encapsulate/decapsulate loop; ' +
          'this is a time-domain legacy key (or corrupted material), not a FIPS 203 key',
      );
    }
  },

  encapsulate(peerPublicKey) {
    kem.assertValidEncapsulationKey(peerPublicKey);
    return MLKEM.encapsulate(peerPublicKey);
  },

  /** KAT/ACVP only: FIPS 203 Encaps_internal. */
  encapsulateDerandomized(peerPublicKey, m) {
    kem.assertValidEncapsulationKey(peerPublicKey);
    return MLKEM.encapsulateDerand(peerPublicKey, m);
  },

  decapsulate(secretKey, ciphertext) {
    if (secretKey.length !== KEM_SIZES.secretKey) {
      throw new InvalidDecapsulationKeyError(`secret key length ${secretKey.length}, expected ${KEM_SIZES.secretKey}`);
    }
    if (ciphertext.length !== KEM_SIZES.ciphertext) {
      throw new InvalidCiphertextError(`ciphertext length ${ciphertext.length}, expected ${KEM_SIZES.ciphertext}`);
    }
    // Implicit rejection is a FIPS 203 property, not an error: a tampered ciphertext yields
    // J(z||c). Callers must not present that value as a successful handshake without an
    // authenticated transcript check.
    return MLKEM.decapsulate(secretKey, ciphertext);
  },
};

module.exports = {
  KEM_ALGORITHM,
  KEM_VERSION,
  KEM_SIZES,
  KemError,
  InvalidEncapsulationKeyError,
  InvalidDecapsulationKeyError,
  InvalidCiphertextError,
  LegacyKemMaterialError,
  isFipsCapable,
  kem,
};
