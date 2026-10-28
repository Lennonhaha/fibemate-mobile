// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 刘天赫
//
// #69 exit criteria, as executable checks instead of a checklist.
//
// The retired set was browser-only (top-level `window.*` reads, so importing it
// outside a browser threw), unreachable from every entry point, and two of the
// files carried the last tracked `Math.random`-seeded jsbn SecureRandom.
//
// Each assertion names the defect it prevents from coming back, so a failure
// here says what re-appeared rather than "expected [] got [...]".

const { test } = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');

const RETIRED = [
  ['src/crypto/message-gm.js', 'browser-only MessageGM duplicate; reads window.SM2EC/SM3Hash/SM4GCM at load'],
  ['src/crypto/sm2-bridge.js', 'browser-only SM2 bridge; stores SM2 keys in localStorage (sm2_key_ prefix)'],
  ['src/crypto/sm2-browser.js', 'sm-crypto wrapper; the only importer was the unused barrel export'],
  ['src/crypto/sm2-browser.esm.js', '@noble/curves SM2 wrapper; no importer'],
  ['src/crypto/sm2-browser.bundle.js', 'minified jsbn build; Math.random-seeded SecureRandom'],
  ['src/crypto/sm2-browser.cjs.js', 'minified jsbn build; Math.random-seeded SecureRandom'],
];

test('the browser-only modules stay retired', () => {
  const back = RETIRED.filter(([file]) => fs.existsSync(path.join(ROOT, file)));
  assert.deepEqual(
    back.map(([file]) => file),
    [],
    'these were retired for the reason listed next to them:\n' +
      back.map(([file, why]) => `  ${file} — ${why}`).join('\n'),
  );
});

test('the barrel does not re-export a retired module', () => {
  const barrel = fs.readFileSync(path.join(ROOT, 'src/crypto/index.ts'), 'utf8');
  const offenders = ['sm2-browser', 'message-gm', 'sm2-bridge'].filter((needle) => barrel.includes(needle));
  assert.deepEqual(offenders, [], `src/crypto/index.ts still references: ${offenders.join(', ')}`);
});

test('the eslint exclusion went away with the files', () => {
  const conf = fs.readFileSync(path.join(ROOT, '.eslintrc.js'), 'utf8');
  assert.ok(
    !conf.includes('sm2-browser'),
    'the ignorePatterns entry for src/crypto/sm2-browser*.js must not survive the deletion: it would silently exempt a re-added file from lint',
  );
});

test('no source file seeds randomness with Math.random', () => {
  const hits = [];
  const walk = (dir) => {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) { walk(full); continue; }
      if (!/\.(js|cjs|mjs|ts|tsx)$/.test(entry.name)) continue;
      const text = fs.readFileSync(full, 'utf8');
      text.split('\n').forEach((line, i) => {
        if (/\bMath\.random\s*\(/.test(line)) hits.push(`${path.relative(ROOT, full)}:${i + 1}`);
      });
    }
  };
  walk(path.join(ROOT, 'src'));
  assert.deepEqual(hits, [], `Math.random is not a cryptographic entropy source (#63): ${hits.join(', ')}`);
});
