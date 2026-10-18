# Security notes — advisories present in the lock file with no upstream fix

This file records dependency advisories that are **present in this repository's
lock file and cannot be resolved by upgrading**, so they are not silently
ignored. Each entry names the advisory, the dependency path, why no fix is
available, and whether the code is reachable from the app. §3 and §4 are not
lock-file advisories: §3 is a **vendored-source** risk, §4 an application-level
fix (with an open server-side half).

Last reviewed: 2026-10-18, against `expo@57.0.30` / `react-native@0.86.3`.

## Summary

`npm audit --json` reports **15** "high" entries for this project. They map to
**two** root advisories (below); the remaining entries are propagation through
the Expo / React Native toolchain — their `via` chains resolve to these two.
GitHub Dependabot reports the same two, as alerts **#47** (node-forge) and
**#48** (braces).

Both are **bundler / CLI-side**: neither appears in the app's import graph
(see "Reachability evidence"), so neither is part of the shipped app bundle.

## 1. braces — GHSA-vfj7-8cjw-p6xm / CVE-2026-93687

| | |
|---|---|
| Vulnerable range | `<= 3.0.3` |
| Registry latest | 3.0.3 |
| `first_patched_version` | `null` (no released fix) |
| Path in this tree | `expo -> @expo/metro -> metro-file-map -> micromatch -> braces@3.0.3` |
| Upstream | micromatch/braces#70 (open) |

Uncontrolled recursion (CWE-674): a deeply nested brace pattern exhausts the
call stack and terminates the process.

## 2. node-forge — GHSA-86w9-cpqp-85rv / CVE-2026-85393

| | |
|---|---|
| Vulnerable range | `<= 1.4.0` |
| Registry latest | 1.4.0 |
| `first_patched_version` | `null` (no released fix) |
| Path in this tree | `expo -> @expo/cli -> @expo/code-signing-certificates -> node-forge@1.4.0` |
| Upstream | digitalbazaar/forge#1149 (open), PR #1152 (open, not merged) |

RSA PKCS#1 v1.5 signature verification accepts extra nested DigestAlgorithm
elements (CWE-347); an incomplete fix for CVE-2026-33894.

## Reachability evidence

```
# node_modules is not tracked, so the denominator is clean
git ls-files | grep -c node_modules        # -> 0

# no tracked file outside the lock file references these packages
git grep -n -e node-forge -e braces -e code-signing-certificates -- .
#   -> 10 lines, all in package-lock.json; 0 outside it

# control: proves the search actually works
git grep -n -e expo-crypto -- .            # -> 7 lines
```

App entry: `index.ts` -> `App.tsx` -> `src/**`, which imports `expo-crypto` and
`expo-secure-store` only. Metro bundles from the import graph, so the
CLI/bundler-side packages above are not included.

`npm ls --omit=dev braces node-forge` still lists both: they sit in the
production dependency tree (under `expo`), not in `devDependencies`. The claim
here is *reachability*, not dependency type.

## Exit criteria

Delete the matching entry once a fixed version is published and installed:

- `braces > 3.0.3`
- `node-forge > 1.4.0`

Then re-run `npm audit --json` and confirm the two advisories are gone.

## 3. Vendored `jsbn` SecureRandom — unreachable; the live SM2 path is fail-closed

Not a lock-file advisory: this is **vendored source** committed to the repo, so
no dependency upgrade changes it. Recorded on 2026-10-15 because it is the same
class of defect as the CodeQL alert `js/insecure-randomness` fixed in
`src/crypto/gm.js` (alert #1).

**Correction (2026-10-17, #63 / #75).** The original framing — "the SM2 path
silently falls back to `Math.random`" — does not hold for the dependency
actually in use:

- `sm-crypto@0.5.7` (installed) is **fail-closed**: with `globalThis.crypto`
  removed, importing its SM2 module throws at load time
  (`当前环境不支持 crypto.getRandomValues！`). With a stub `getRandomValues` the
  module loads and `Math.random` is called **0** times — the jsbn pool is present
  but not on the SM2 call path.
- The real defect was that **no entropy source was wired at all** on React
  Native. Fixed in #75: `src/polyfills/crypto.ts` installs a native
  `globalThis.crypto.getRandomValues` (backed by `expo-crypto`) before
  `App -> screens -> sm-crypto` are evaluated. The installer never overwrites a
  usable `getRandomValues`, rejects a broken source, and fails closed.
- The `Math.random`-backed pool below still exists, but only inside files that
  nothing imports.

| | |
|---|---|
| Files | `src/crypto/sm2-browser.bundle.js` (39,782 B), `src/crypto/sm2-browser.cjs.js` (39,731 B) — minified jsbn builds; no importer |
| Site | the `SecureRandom` seed pool: when `window.crypto` is unavailable the pool is filled from `Math.random()`; `millerRabin` also picks bases with `Math.random()` |
| Live path | **not this code.** The app's SM2 calls go to `sm-crypto` directly; `sm-crypto@0.5.7` is fail-closed and, since #75, always finds a real `getRandomValues` |
| Latent risk | none in the shipped bundle: the files are unreachable and outside the app's import graph. They are the last tracked `Math.random` hits in `src/` |
| Status | **closed client-side** — #63 closed on 2026-10-18 on the strength of #75; the vendored files moved into the browser-only retirement scope of `#69` (scope extended 2026-10-18) |
| Exit criteria | `git grep -c --untracked Math.random -- src` reports no tracked source hits, i.e. the two bundles are deleted and the eslint exclusion at `.eslintrc.js:21` goes with them |

#63 is closed because the security-relevant defect (the missing entropy source)
is fixed by #75. What remains is dead-code removal, tracked in #69; the
grep-based exit criterion above is deliberately left unmet until that lands.

## 4. SM2 private key published as the registered identity key — client-side interception

Application-level defect, not a dependency advisory. Recorded on 2026-10-17
(issue `#68`). The fix is **client-side interception only**: the wire protocol
and the server are unchanged, and nothing here is a claim about peer identity.

| | |
|---|---|
| Site (before) | `src/services/regClient.ts` read `identity` → `sm2.privateKey` and published it as the `identityKey` field of `register`; `lookupUser` handed the stored value straight back out |
| Consumer | `src/screens/MessageScreen.tsx` cached it as the peer's encryption key, and fell back to **its own** public key (`recipientPubKeyCache \|\| myPubKey`) when the lookup failed |
| Fixed | `register` publishes `sm2.publicKey` and fails closed unless it is an uncompressed SM2 public point (`04 ‖ X ‖ Y`, 130 hex); `regClient.ts` no longer reads `sm2.privateKey` at all; `lookupUser` validates the returned key before handing it out; the send path blocks instead of encrypting to a key of our own |
| Status | **open on the server side** — `Lennonhaha/fibemate#263` (the reg-server stores and returns `identityKey` without validating it, and the field's role is still undefined) |
| Residual risk | records written before this fix hold a private key, so peers cannot encrypt to them; `init()` skips `register` when a local `fibemate_reg_userId` exists, so existing installs do not re-publish a public key. Migration (client re-register vs server-side rewrite) is undecided |

### Evidence

```
# the private key is gone from the registration client (same command, control file still hits)
git grep -n privateKey -- src/services/regClient.ts   # -> 0 lines (rc=1)
git grep -n privateKey -- src/services/keyService.ts  # -> control: hits

# shape tests + source guards run under the node:test gate
node --no-warnings --test test/*.node.cjs             # -> 49 pass / 0 fail
```

`test/sm2key-format.node.cjs` pins the two shapes and asserts against the client
sources that `regClient.ts` never reads `sm2.privateKey` and that
`MessageScreen.tsx` keeps the no-fallback send guard.

