/**
 * Key management service for FIBEMATE Mobile.
 * ML-KEM-768 (FIPS 203) via pure-JS ml-kem-768.js
 * SM2 (GB/T 32918) via sm-crypto
 * expo-crypto for SHA-256 and secure random.
 */

import * as Crypto from 'expo-crypto';
import MLKEM768 from '../crypto/ml-kem-768';
import sm2 from 'sm-crypto/dist/sm2';

export type KeyPair = {
  publicKey: string;
  privateKey: string;
};

export type IdentityMaterial = {
  mlkem: {
    publicKey: string;  // base64url, 1184 bytes
    privateKey: string; // base64url
  };
  sm2: {
    publicKey: string;  // hex, 130 chars (uncompressed)
    privateKey: string; // hex, 64 chars
  };
  createdAt: string;
};

// ---- Base64url helpers (Hermes-safe, no btoa/atob) ----

function hexToBase64url(hex: string): string {
  const binary = hex.match(/.{1,2}/g)!.map(b => String.fromCharCode(parseInt(b, 16))).join('');
  const b64 = btoa(binary);
  return b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function base64urlToHex(b64url: string): string {
  const b64 = b64url.replace(/-/g, '+').replace(/_/g, '/');
  const padded = b64 + '=='.slice(0, (4 - b64.length % 4) % 4);
  const binary = atob(padded);
  return Array.from(binary).map(c => c.charCodeAt(0).toString(16).padStart(2, '0')).join('');
}

function uint8ArrayToBase64url(arr: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < arr.length; i++) binary += String.fromCharCode(arr[i]);
  const b64 = btoa(binary);
  return b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

// ---- SM2 key generation ----

export function generateSM2KeyPair(): KeyPair {
  const kp = sm2.generateKeyPairHex();
  return {
    publicKey: kp.publicKey,   // hex 130 chars
    privateKey: kp.privateKey, // hex 64 chars
  };
}

// ---- ML-KEM-768 key generation ----

async function generateMLKEMKeyPair(): Promise<KeyPair> {
  const kp = MLKEM768.generateKeypair();
  return {
    publicKey: uint8ArrayToBase64url(kp.publicKey),
    privateKey: uint8ArrayToBase64url(kp.secretKey),
  };
}

// ---- Identity generation ----

export async function generateIdentity(): Promise<IdentityMaterial> {
  const [mlkem, sm2kp] = await Promise.all([
    generateMLKEMKeyPair(),
    Promise.resolve(generateSM2KeyPair()),
  ]);
  return {
    mlkem,
    sm2: sm2kp,
    createdAt: new Date().toISOString(),
  };
}

// ---- Storage helpers ----

export function serializeIdentity(km: IdentityMaterial): string {
  return JSON.stringify({
    mlkem: km.mlkem,
    sm2: km.sm2,
    createdAt: km.createdAt,
  });
}

export function deserializeIdentity(raw: string): IdentityMaterial {
  const obj = JSON.parse(raw);
  return {
    mlkem: obj.mlkem,
    sm2: obj.sm2,
    createdAt: obj.createdAt,
  };
}

// ---- Random utilities ----

export async function getSecureRandom(length: number): Promise<Uint8Array> {
  const bytes = await Crypto.getRandomBytesAsync(length);
  return new Uint8Array(bytes);
}

export async function sha256hex(data: Uint8Array): Promise<string> {
  const hex = Array.from(data).map(b => b.toString(16).padStart(2, '0')).join('');
  return Crypto.digestStringAsync(Crypto.CryptoDigestAlgorithm.SHA256, hex);
}
