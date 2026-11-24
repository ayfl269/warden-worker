import { pbkdf2Sync } from 'node:crypto';
import { pbkdf2 as noblePbkdf2 } from '@noble/hashes/pbkdf2.js';
import { sha256 } from '@noble/hashes/sha2.js';

import { base64ToBytes, bytesToBase64 } from './base64';
import { pbkdf2Wasm } from './pbkdf2Wasm';

/** Salt length in bytes for server-side password hashing (`crypto.rs`). */
export const PASSWORD_SALT_LENGTH = 64;

/** Derived key length: 256 bits. */
const KEY_LENGTH_BYTES = 32;

/**
 * Whether `node:crypto.pbkdf2Sync` can be used in this isolate.
 *
 * WebCrypto's PBKDF2 rejects iteration counts above 100k in production, but
 * `node:crypto` is backed by BoringSSL and has no such cap. If the native path
 * ever throws we permanently fall back to the pure-JS implementation, which
 * produces identical bytes at a higher CPU cost.
 */
let useNativePbkdf2 = true;

/** Exposed for diagnostics/tests. */
export function isUsingNativePbkdf2(): boolean {
  return useNativePbkdf2;
}

function deriveKey(
  password: Uint8Array,
  salt: Uint8Array,
  iterations: number,
): Uint8Array {
  const fromWasm = pbkdf2Wasm(password, salt, iterations);
  if (fromWasm !== null) return fromWasm;

  return deriveKeyFallback(password, salt, iterations);
}

function deriveKeyFallback(password: Uint8Array, salt: Uint8Array, iterations: number): Uint8Array {
  if (useNativePbkdf2) {
    try {
      return new Uint8Array(pbkdf2Sync(password, salt, iterations, KEY_LENGTH_BYTES, 'sha256'));
    } catch (error) {
      useNativePbkdf2 = false;
      console.warn(
        '[crypto] node:crypto pbkdf2Sync unavailable; falling back to @noble/hashes',
        error,
      );
    }
  }

  return noblePbkdf2(sha256, password, salt, { c: iterations, dkLen: KEY_LENGTH_BYTES });
}

/** PBKDF2-HMAC-SHA256, matching `crypto::pbkdf2_sha256`. */
export function pbkdf2Sha256(
  password: Uint8Array,
  salt: Uint8Array,
  iterations: number,
): Uint8Array {
  return deriveKey(password, salt, iterations);
}

/** Cryptographically secure random salt, base64 (STANDARD, padded). */
export function generateSalt(): string {
  const salt = new Uint8Array(PASSWORD_SALT_LENGTH);
  crypto.getRandomValues(salt);
  return bytesToBase64(salt);
}

/**
 * Hash the client-provided master password hash for storage.
 *
 * The stored value is base64 (STANDARD) of PBKDF2-HMAC-SHA256 over the
 * client hash bytes, using the per-user salt and iteration count.
 */
export function hashPasswordForStorage(
  clientPasswordHash: string,
  salt: string,
  iterations: number,
): string {
  const saltBytes = base64ToBytes(salt);
  const derived = deriveKey(new TextEncoder().encode(clientPasswordHash), saltBytes, iterations);
  return bytesToBase64(derived);
}

/** Constant-time comparison of the base64-encoded hashes. */
export function verifyPassword(
  clientPasswordHash: string,
  storedHash: string,
  salt: string,
  iterations: number,
): boolean {
  const computed = hashPasswordForStorage(clientPasswordHash, salt, iterations);
  return constantTimeEqual(computed, storedHash);
}

/**
 * Constant-time string comparison over UTF-8 bytes.
 * Mirrors `constant_time_eq` on byte slices (different lengths → false).
 */
export function constantTimeEqual(left: string, right: string): boolean {
  const leftBytes = new TextEncoder().encode(left);
  const rightBytes = new TextEncoder().encode(right);
  if (leftBytes.length !== rightBytes.length) return false;

  let difference = 0;
  for (let index = 0; index < leftBytes.length; index += 1) {
    difference |= (leftBytes[index] as number) ^ (rightBytes[index] as number);
  }
  return difference === 0;
}
