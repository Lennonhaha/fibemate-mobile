# Security notes — advisories present in the lock file with no upstream fix

This file records dependency advisories that are **present in this repository's
lock file and cannot be resolved by upgrading**, so they are not silently
ignored. Each entry names the advisory, the dependency path, why no fix is
available, and whether the code is reachable from the app. §3 records a
**vendored-source** risk instead (not a lock-file advisory).

Last reviewed: 2026-10-14, against `expo@57.0.28` / `react-native@0.86.3`.

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

## 3. Vendored `jsbn` SecureRandom — weak-randomness fallback

Not a lock-file advisory: this is **vendored source** committed to the repo, so
no dependency upgrade changes it. Recorded on 2026-10-15 because it is the same
class of defect as the CodeQL alert `js/insecure-randomness` fixed in
`src/crypto/gm.js` (alert #1); it is deliberately **out of scope** for that fix
and tracked separately.

| | |
|---|---|
| Files | `src/crypto/sm2-browser.bundle.js`, `src/crypto/sm2-browser.cjs.js` (minified builds of `jsbn`) |
| Site | the `SecureRandom` seed pool: when `window.crypto` is unavailable the pool is filled from `Math.random()`; `millerRabin` also picks bases with `Math.random()` |
| Trigger | only when WebCrypto (`window.crypto.getRandomValues`) is unavailable |
| Impact if triggered | SM2 key material / signature nonces drawn from a non-cryptographic PRNG |
| Reachability | the jsbn-based SM2 path (`sm2-browser*`). The app also ships `expo-crypto`, so WebCrypto is normally present — treated as a **latent** risk |
| Status | **open — tracked separately** (vendor bundle; not covered by the entropy-centralization change) |
| Exit criteria | a patched vendor build whose `SecureRandom` is fail-closed, or routing SM2 randomness through `src/crypto/entropy.js` |

