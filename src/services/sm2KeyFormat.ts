/**
 * SM2 key shapes used on the wire by the registration client.
 *
 * sm-crypto's generateKeyPairHex() returns:
 *   publicKey  130 hex chars — uncompressed point, 04 || X(64) || Y(64)
 *   privateKey  64 hex chars — the secret scalar
 *
 * The backend's `identityKey` field is meant to carry the *public* key: it is
 * what a peer caches and encrypts to. Keeping the two shapes distinguishable
 * here is what lets the client refuse to transmit, cache or encrypt with a
 * private key by mistake.
 */

export const SM2_PUBLIC_KEY_HEX = /^04[0-9a-fA-F]{128}$/;
export const SM2_PRIVATE_KEY_HEX = /^[0-9a-fA-F]{64}$/;

/** True only for an uncompressed SM2 public point (04 || X || Y, 130 hex). */
export function isSm2PublicKeyHex(value: unknown): boolean {
  return typeof value === 'string' && SM2_PUBLIC_KEY_HEX.test(value);
}

/** True only for a bare 64-hex SM2 private scalar. */
export function isSm2PrivateKeyHex(value: unknown): boolean {
  return typeof value === 'string' && SM2_PRIVATE_KEY_HEX.test(value);
}
