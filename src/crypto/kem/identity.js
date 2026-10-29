/**
 * Identity-record handling for the ML-KEM clean break.
 *
 * Pure CJS: no Expo, no storage, no React Native imports, so `node --test` can run the
 * rotation logic directly.
 *
 * Policy: a record written before this change has no `kem.version` marker. It is rotated
 * once (new KEM keypair, SM2 identity preserved) and a marker is written. Legacy material
 * is never handed back to a caller.
 */

'use strict';

const { kem, KEM_VERSION, LegacyKemMaterialError } = require('./engine');

function toBase64url(bytes) {
  let binary = '';
  for (let i = 0; i < bytes.length; i += 1) binary += String.fromCharCode(bytes[i]);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/[=]+$/, '');
}

function fromBase64url(value) {
  const b64 = value.replace(/-/g, '+').replace(/_/g, '/');
  const padded = b64 + '='.repeat((4 - (b64.length % 4)) % 4);
  const binary = atob(padded);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) out[i] = binary.charCodeAt(i);
  return out;
}

function parseRecord(raw) {
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new Error('identity record is not valid JSON; refusing to rotate it');
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new Error('identity record is not a JSON object; refusing to rotate it');
  }
  return parsed;
}

function declaredVersion(record) {
  if (!record.mlkem) return 'missing';
  return record.mlkem.version === KEM_VERSION ? KEM_VERSION : 'v1_legacy';
}

function isFipsCapableSafe(privateKeyBase64url) {
  const secretKey = fromBase64url(privateKeyBase64url);
  if (secretKey.length !== kem.sizes.secretKey) return false;
  try {
    kem.assertFipsCapable(secretKey);
    return true;
  } catch {
    return false;
  }
}

/**
 * Rotates the KEM keypair when the record cannot prove it holds a working FIPS 203 key.
 * Idempotent: a record already marked v2_fips whose key passes the functional probe is
 * returned untouched.
 *
 * @param {string | null} raw
 * @param {() => string} [now]
 * @returns {{ raw: string | null, rotated: boolean, reason: string | null, version: string | null }}
 */
function ensureFipsIdentity(raw, now) {
  const timestamp = now || (() => new Date().toISOString());
  if (raw === null || raw === undefined) {
    return { raw: null, rotated: false, reason: null, version: null };
  }

  const record = parseRecord(raw);
  const declared = declaredVersion(record);

  if (declared === KEM_VERSION && record.mlkem) {
    let capable = false;
    try {
      capable = isFipsCapableSafe(record.mlkem.privateKey);
    } catch {
      capable = false;
    }
    if (capable) {
      return { raw, rotated: false, reason: null, version: KEM_VERSION };
    }
  }

  const reason = declared === 'missing' ? 'missing' : declared === 'v1_legacy' ? 'v1_legacy' : 'not_fips_capable';

  const keypair = kem.generateKeypair();
  // Never persist a key that cannot pass its own round trip.
  kem.assertFipsCapable(keypair.secretKey);

  const next = Object.assign({}, record, {
    mlkem: {
      version: KEM_VERSION,
      publicKey: toBase64url(keypair.publicKey),
      privateKey: toBase64url(keypair.secretKey),
    },
    kemRotatedAt: timestamp(),
  });

  return { raw: JSON.stringify(next), rotated: true, reason, version: KEM_VERSION };
}

/** Throws instead of returning legacy material to a caller. */
function assertFipsIdentity(raw, source) {
  const record = parseRecord(raw);
  if (declaredVersion(record) !== KEM_VERSION) {
    throw new LegacyKemMaterialError(
      source || 'stored_identity',
      'identity record has no v2_fips marker; rotate it with ensureFipsIdentity() before use',
    );
  }
  return record;
}

module.exports = {
  ensureFipsIdentity,
  assertFipsIdentity,
  toBase64url,
  fromBase64url,
};
