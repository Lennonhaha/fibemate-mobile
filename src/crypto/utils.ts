/**
 * FIBEMATE Mobile — 通用工具函数
 */

/** Uint8Array → hex */
export function uint8ArrayToHex(arr: Uint8Array): string {
  return Array.from(arr).map(b => b.toString(16).padStart(2, '0')).join('');
}
