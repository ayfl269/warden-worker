import { pbkdf2 as noblePbkdf2 } from '@noble/hashes/pbkdf2.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { describe, expect, it } from 'vitest';

import { base64ToBytes, bytesToBase64 } from '../../src/auth/base64';
import {
  constantTimeEqual,
  generateSalt,
  hashPasswordForStorage,
  isUsingNativePbkdf2,
  PASSWORD_SALT_LENGTH,
  pbkdf2Sha256,
  verifyPassword,
} from '../../src/auth/password';

function toHex(bytes: Uint8Array): string {
  return [...bytes].map((byte) => byte.toString(16).padStart(2, '0')).join('');
}

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let index = 0; index < bytes.length; index += 1) {
    bytes[index] = Number.parseInt(hex.slice(index * 2, index * 2 + 2), 16);
  }
  return bytes;
}

function utf8(value: string): Uint8Array {
  return new TextEncoder().encode(value);
}

/**
 * Published PBKDF2-HMAC-SHA256 test vectors (P="password", S="salt", dkLen=32).
 * The Rust implementation uses `pbkdf2_hmac::<Sha256>`, which is the same
 * standard construction, so matching these vectors proves byte-level parity.
 */
const VECTORS = [
  [1, '120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b'],
  [2, 'ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43'],
  [4096, 'c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a'],
] as const;

describe('pbkdf2Sha256', () => {
  for (const [iterations, expected] of VECTORS) {
    it(`matches the published vector for c=${iterations}`, () => {
      const derived = pbkdf2Sha256(utf8('password'), utf8('salt'), iterations);
      expect(derived).toHaveLength(32);
      expect(toHex(derived)).toBe(expected);
    });
  }

  it('agrees with the @noble/hashes fallback implementation', () => {
    for (const [iterations, expected] of VECTORS) {
      const noble = noblePbkdf2(sha256, utf8('password'), utf8('salt'), {
        c: iterations,
        dkLen: 32,
      });
      expect(toHex(noble)).toBe(expected);
    }
  });

  it('uses the native node:crypto path on this runtime', () => {
    pbkdf2Sha256(utf8('password'), utf8('salt'), 1);
    expect(isUsingNativePbkdf2()).toBe(true);
  });

  it('derives a 32-byte key at the production iteration count', () => {
    const derived = pbkdf2Sha256(utf8('client-hash'), new Uint8Array(64).fill(7), 600_000);
    expect(derived).toHaveLength(32);
  });
});

describe('generateSalt', () => {
  it('returns 64 random bytes encoded as padded base64', () => {
    const salt = generateSalt();
    expect(salt).toHaveLength(88); // 64 bytes → ceil(64/3)*4
    expect(base64ToBytes(salt)).toHaveLength(PASSWORD_SALT_LENGTH);
    expect(generateSalt()).not.toBe(salt);
  });
});

describe('hashPasswordForStorage', () => {
  it('base64-encodes the derived key (STANDARD, padded)', () => {
    const salt = bytesToBase64(utf8('salt'));
    const stored = hashPasswordForStorage('password', salt, 4096);
    expect(stored).toBe(bytesToBase64(hexToBytes(VECTORS[2][1])));
  });

  it('round-trips through verifyPassword', () => {
    const salt = generateSalt();
    const stored = hashPasswordForStorage('client-hash', salt, 1_000);

    expect(verifyPassword('client-hash', stored, salt, 1_000)).toBe(true);
    expect(verifyPassword('client-hash', stored, salt, 999)).toBe(false);
    expect(verifyPassword('other-hash', stored, salt, 1_000)).toBe(false);
  });
});

describe('constantTimeEqual', () => {
  it('compares equal and unequal strings', () => {
    expect(constantTimeEqual('abc', 'abc')).toBe(true);
    expect(constantTimeEqual('abc', 'abd')).toBe(false);
    expect(constantTimeEqual('abc', 'abcd')).toBe(false);
    expect(constantTimeEqual('', '')).toBe(true);
  });
});
