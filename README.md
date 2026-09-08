# FIBEMATE Mobile (Expo)

> Post-Quantum secure messaging — mobile client (Expo / React Native).

**Status:** WIP (pre-release). Actively developed alongside the
[FIBEMATE](https://github.com/Lennonhaha/fibemate) backend.

FIBEMATE is a Post-Quantum Cryptography (PQC) engineering-validation platform. The
mobile client implements the end-user messaging surface with hybrid PQC key
establishment (ML-KEM-768 + X25519) and SM2 (GB/T 32918) identity crypto.

## Tech stack

- **Expo** + **React Native** + **TypeScript**
- **ML-KEM-768** (FIPS 203) — pure-JS implementation (`src/crypto/ml-kem-768`)
- **SM2 / SM3 / SM4** (GB/T 32918 / 32905 / 32907) via `sm-crypto`
- **X3DH-style** OPK pool using X25519 (from `@noble/curves`) for one-time pre-keys
- Async storage for key material (`@react-native-async-storage/async-storage`)

## Relation to other FIBEMATE repositories

| Repository | Role |
|------------|------|
| [`fibemate`](https://github.com/Lennonhaha/fibemate) | Backend API + web demo (authoritative server) |
| [`fibemate-tauri`](https://github.com/Lennonhaha/fibemate-tauri) | Desktop app (Rust / Tauri) |
| [`fibemate-react-native`](https://github.com/Lennonhaha/fibemate-react-native) | RN CLI crypto self-test panel |
| `fibemate-mobile` | This repo — Expo mobile client (UI + messaging) |

## Quick start

```bash
npm install
npx expo start
```

Then open the app with the Expo Go client, an emulator, or a development build.

## Security status

- Hybrid PQC key exchange and SM2 identity crypto are implemented; the mobile
  client is **not yet production-hardened** (see the backend
  [`security-limitations.md`](https://github.com/Lennonhaha/fibemate/blob/main/docs/security-limitations.md)).
- CI runs `eslint`, `tsc --noEmit`, and `jest` on every push/PR.

## License

[GPL-3.0-only](./LICENSE) — Copyright (c) 2026 Lennonhaha.
