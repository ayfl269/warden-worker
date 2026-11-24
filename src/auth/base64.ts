/**
 * Base64 helpers.
 *
 * The Rust implementation uses three distinct alphabets; each one matters for
 * wire compatibility, so they are kept as explicit, named helpers:
 *
 * - `base64`          → STANDARD (with padding): password salt + password hash
 * - `base64Url`       → URL_SAFE (with padding): device refresh token
 * - `base64UrlNoPad`  → URL_SAFE_NO_PAD: send password hash/salt, send access id
 */

export function bytesToBase64(bytes: Uint8Array): string {
  let binary = '';
  const chunkSize = 0x8000;
  for (let offset = 0; offset < bytes.length; offset += chunkSize) {
    binary += String.fromCharCode(...bytes.subarray(offset, offset + chunkSize));
  }
  return btoa(binary);
}

export function base64ToBytes(value: string): Uint8Array {
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }
  return bytes;
}

/** URL_SAFE with padding, matching `base64::engine::general_purpose::URL_SAFE`. */
export function bytesToBase64Url(bytes: Uint8Array): string {
  return bytesToBase64(bytes).replace(/\+/g, '-').replace(/\//g, '_');
}

export function base64UrlToBytes(value: string): Uint8Array {
  return base64ToBytes(value.replace(/-/g, '+').replace(/_/g, '/'));
}

/** URL_SAFE_NO_PAD, matching `URL_SAFE_NO_PAD`. */
export function bytesToBase64UrlNoPad(bytes: Uint8Array): string {
  return bytesToBase64Url(bytes).replace(/=+$/, '');
}

export function base64UrlNoPadToBytes(value: string): Uint8Array {
  const normalized = value.replace(/-/g, '+').replace(/_/g, '/');
  const remainder = normalized.length % 4;
  const padding = remainder === 0 ? '' : '='.repeat(4 - remainder);
  return base64ToBytes(normalized + padding);
}
