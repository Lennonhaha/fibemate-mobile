// sm-crypto — 无官方类型声明
declare module 'sm-crypto/dist/sm2' {
  export function generateKeyPairHex(): { publicKey: string; privateKey: string };
  export function doEncrypt(msg: string, publicKey: string, cipherMode?: number): string;
  export function doDecrypt(ciphertext: string, privateKey: string, cipherMode?: number): string;
  export function doSignature(msg: string, privateKey: string): string;
  export function doVerifySignature(msg: string, signature: string, publicKey: string): boolean;
}
