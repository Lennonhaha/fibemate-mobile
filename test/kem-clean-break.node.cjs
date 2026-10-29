'use strict';

/**
 * Tests for the ML-KEM clean break (mobile#94, design: docs/design/mobile-kem-migration.md).
 *
 * Gates:
 *   1. the vendored FIPS 203 engine is byte-identical to @noble/post-quantum on fixed seeds;
 *   2. a keypair from the retired engine passes FIPS 203 encoding checks but is rejected by
 *      the functional probe — and would otherwise return a plausible-looking wrong secret;
 *   3. identity records written before the change rotate once, idempotently, keeping SM2;
 *   4. the legacy module is gone and nothing imports it.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');
const kemDir = path.join(ROOT, 'src', 'crypto', 'kem');
const { kem, LegacyKemMaterialError, InvalidEncapsulationKeyError, KEM_VERSION, isFipsCapable } = require(path.join(kemDir, 'engine.js'));
const MLKEM = require(path.join(kemDir, 'vendor', 'ml-kem-768.js'));
const { ensureFipsIdentity } = require(path.join(kemDir, 'identity.js'));

let noble = null;
try {
  // eslint-disable-next-line global-require
  noble = require('@noble/post-quantum/ml-kem.js').ml_kem768;
} catch {
  noble = null;
}

const fixture = JSON.parse(fs.readFileSync(path.join(__dirname, 'fixtures', 'legacy-mlkem-768.json'), 'utf8'));
const fromB64 = (s) => Uint8Array.from(Buffer.from(s, 'base64'));
const legacyPk = fromB64(fixture.publicKey);
const legacySk = fromB64(fixture.secretKey);

const seq = (start, n) => {
  const out = new Uint8Array(n);
  for (let i = 0; i < n; i += 1) out[i] = (start + i) & 0xff;
  return out;
};
const concat = (...parts) => Uint8Array.from(Buffer.concat(parts.map((p) => Buffer.from(p))));
const hex = (b) => Buffer.from(b).toString('hex');

test('oracle: engine is byte-identical to @noble/post-quantum on 3 fixed seeds', { skip: noble === null }, () => {
  for (let i = 0; i < 3; i += 1) {
    const d = seq(0x10 + i, 32);
    const z = seq(0x80 + i, 32);
    const m = seq(0x40 + i, 32);

    const ours = kem.deriveKeypair(d, z);
    const ref = noble.keygen(concat(d, z));

    assert.equal(hex(ours.publicKey), hex(ref.publicKey), `seed ${i}: pk`);
    assert.equal(hex(ours.secretKey), hex(ref.secretKey), `seed ${i}: sk`);

    const enc = kem.encapsulateDerandomized(ours.publicKey, m);
    const refEnc = noble.encapsulate(ref.publicKey, m);
    assert.equal(hex(enc.ciphertext), hex(refEnc.cipherText), `seed ${i}: ct`);
    assert.equal(hex(enc.sharedSecret), hex(refEnc.sharedSecret), `seed ${i}: ss`);

    assert.equal(hex(kem.decapsulate(ours.secretKey, enc.ciphertext)), hex(enc.sharedSecret), `seed ${i}: rt`);
    // Cross-implementation decapsulation in both directions.
    assert.equal(hex(noble.decapsulate(enc.ciphertext, ref.secretKey)), hex(enc.sharedSecret), `seed ${i}: noble decaps`);
    assert.equal(hex(kem.decapsulate(ref.secretKey, refEnc.cipherText)), hex(refEnc.sharedSecret), `seed ${i}: ours decaps`);
  }
});

test('legacy secret key passes every structural check — the probe is what catches it', () => {
  assert.equal(MLKEM.decapsKeyCheck(legacySk), true, 'legacy sk passes FIPS 203 §7.3 encoding checks');
  assert.equal(kem.isValidEncapsulationKey(legacyPk), true, 'legacy pk passes FIPS 203 §7.2 checks');
  assert.equal(isFipsCapable(legacySk), false, 'functional probe rejects it');

  assert.throws(
    () => kem.assertFipsCapable(legacySk),
    (err) => {
      assert.ok(err instanceof LegacyKemMaterialError, 'expected LegacyKemMaterialError');
      assert.equal(err.code, 'legacy_kem_material');
      assert.equal(err.source, 'secret_key');
      return true;
    },
  );
});

test('legacy keypair would return a rejection value instead of the secret (why the probe exists)', () => {
  const m = seq(0x40, 32);
  const enc = kem.encapsulateDerandomized(legacyPk, m); // legacy pk is accepted structurally
  const opened = kem.decapsulate(legacySk, enc.ciphertext);

  assert.notEqual(hex(opened), hex(enc.sharedSecret), 'must not equal the encapsulated secret');
  const z = legacySk.subarray(legacySk.length - 32);
  const rejection = MLKEM.shake256(concat(z, enc.ciphertext), 32);
  assert.equal(hex(opened), hex(rejection), "equals J(z||c) = SHAKE256(z||ct, 32)");
});

test('structurally invalid encapsulation keys are rejected before any ciphertext is produced', () => {
  assert.throws(() => kem.encapsulate(new Uint8Array(1183)), InvalidEncapsulationKeyError);
  const nonCanonical = new Uint8Array(legacyPk);
  nonCanonical.fill(0xff, 0, 384); // 0xfff decodes but does not re-encode canonically
  assert.throws(() => kem.encapsulate(nonCanonical), InvalidEncapsulationKeyError);
});

test('identity rotation: legacy record is re-keyed once, SM2 preserved, marker written', () => {
  const raw = JSON.stringify({
    mlkem: { publicKey: fixture.publicKey, privateKey: fixture.secretKey }, // no version field
    sm2: { publicKey: '04aa', privateKey: 'bb' },
    createdAt: '2026-10-01T00:00:00.000Z',
  });

  const first = ensureFipsIdentity(raw, () => '2026-10-29T00:00:00.000Z');
  assert.equal(first.rotated, true);
  assert.equal(first.reason, 'v1_legacy');
  assert.equal(first.version, KEM_VERSION);

  const next = JSON.parse(first.raw);
  assert.equal(next.mlkem.version, KEM_VERSION);
  assert.equal(next.sm2.publicKey, '04aa', 'SM2 identity must survive the rotation');
  assert.equal(next.createdAt, '2026-10-01T00:00:00.000Z');
  assert.equal(next.kemRotatedAt, '2026-10-29T00:00:00.000Z');
  assert.notEqual(next.mlkem.privateKey, fixture.secretKey, 'old KEM private key must be gone');

  const rotatedSk = Uint8Array.from(Buffer.from(next.mlkem.privateKey.replace(/-/g, '+').replace(/_/g, '/'), 'base64'));
  assert.doesNotThrow(() => kem.assertFipsCapable(rotatedSk), 'rotated key must pass the probe');

  const second = ensureFipsIdentity(first.raw);
  assert.equal(second.rotated, false, 'second run must be a no-op');
  assert.equal(second.raw, first.raw);
});

test('identity rotation: records without ML-KEM material are filled in; corrupt JSON is refused', () => {
  const noKem = JSON.stringify({ sm2: { publicKey: '04aa', privateKey: 'bb' }, createdAt: '2026-10-01T00:00:00.000Z' });
  const result = ensureFipsIdentity(noKem);
  assert.equal(result.rotated, true);
  assert.equal(result.reason, 'missing');
  assert.equal(JSON.parse(result.raw).mlkem.version, KEM_VERSION);

  assert.throws(() => ensureFipsIdentity('{not json'), /refusing to rotate/);
  assert.throws(() => ensureFipsIdentity('[]'), /refusing to rotate/);
});

test('the retired engine is gone and nothing imports it', () => {
  assert.equal(fs.existsSync(path.join(ROOT, 'src', 'crypto', 'ml-kem-768.js')), false);
  assert.equal(fs.existsSync(path.join(ROOT, 'src', 'crypto', 'pqc-hybrid-client.js')), false);

  const offenders = [];
  const walk = (dir) => {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        if (entry.name === 'node_modules') continue;
        walk(full);
        continue;
      }
      if (!/\.(ts|tsx|js|cjs)$/.test(entry.name)) continue;
      if (full.includes(path.join('kem', 'vendor'))) continue; // the FIPS module's own file name
      const text = fs.readFileSync(full, 'utf8');
      if (/from\s+['"][^'"]*ml-kem-768['"]/.test(text) || /require\(['"][^'"]*ml-kem-768['"]\)/.test(text)) {
        if (!full.endsWith(path.join('kem', 'vendor', 'ml-kem-768.js'))) offenders.push(full);
      }
      if (text.includes('pqc-hybrid-client')) offenders.push(`${full} (pqc-hybrid-client)`);
    }
  };
  walk(path.join(ROOT, 'src'));
  assert.deepEqual(offenders, []);
});
