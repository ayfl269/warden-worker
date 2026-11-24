import { createHmac } from 'node:crypto';

import { AppError } from '../errors';
import { constantTimeEqual } from './password';

const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
const BASE32_LOOKUP: Readonly<Record<string, number>> = Object.fromEntries(
  [...BASE32_ALPHABET].map((char, index) => [char, index]),
);

const TOTP_TIME_STEP_SECONDS = 30;
const TOTP_DIGITS = 6;
const TOTP_SECRET_BYTES = 20;
const RECOVERY_CODE_BYTES = 20;

/** RFC 4648 Base32, uppercase, with `=` padding. */
export function base32Encode(data: Uint8Array): string {
  let bits = 0;
  let value = 0;
  let output = '';

  for (const byte of data) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      output += BASE32_ALPHABET[(value >>> (bits - 5)) & 0x1f];
      bits -= 5;
    }
  }

  if (bits > 0) {
    output += BASE32_ALPHABET[(value << (5 - bits)) & 0x1f];
  }

  while (output.length % 8 !== 0) output += '=';
  return output;
}

/**
 * Decode Base32, accepting both padded and unpadded input.
 * Throws a 500 `Crypto error` for invalid input, like `crypto::base32_decode`.
 */
export function base32Decode(input: string): Uint8Array {
  const normalized = input.replace(/=+$/, '');
  const bytes: number[] = [];
  let bits = 0;
  let value = 0;

  for (const char of normalized) {
    const index = BASE32_LOOKUP[char];
    if (index === undefined) {
      throw AppError.crypto('Invalid Base32 input');
    }
    value = (value << 5) | index;
    bits += 5;
    if (bits >= 8) {
      bytes.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }

  return new Uint8Array(bytes);
}

function hmacSha1(key: Uint8Array, data: Uint8Array): Uint8Array {
  return new Uint8Array(createHmac('sha1', key).update(data).digest());
}

/** Generate the 6-digit TOTP for a given time step (RFC 4226 dynamic truncation). */
export function generateTotp(secret: string, timeStep: number): string {
  const key = base32Decode(secret);

  const counter = new Uint8Array(8);
  const view = new DataView(counter.buffer);
  view.setBigUint64(0, BigInt(timeStep), false);

  const digest = hmacSha1(key, counter);
  const offset = (digest[19] as number) & 0x0f;
  const binary =
    (((digest[offset] as number) & 0x7f) << 24) |
    ((digest[offset + 1] as number) << 16) |
    ((digest[offset + 2] as number) << 8) |
    (digest[offset + 3] as number);

  return String(binary % 10 ** TOTP_DIGITS).padStart(TOTP_DIGITS, '0');
}

/**
 * Validate a TOTP code.
 *
 * Returns the matched time step (to be persisted as `last_used`), or throws:
 * - 400 `Invalid TOTP code format` for non-6-digit input
 * - 401 `Invalid TOTP code.` when no step matches
 */
export function validateTotp(
  code: string,
  secret: string,
  lastUsed: number,
  allowDrift: boolean,
): number {
  if (!/^\d{6}$/.test(code)) {
    throw AppError.badRequest('Invalid TOTP code format');
  }

  const currentStep = Math.floor(Date.now() / 1000 / TOTP_TIME_STEP_SECONDS);
  const drift = allowDrift ? 1 : 0;

  for (let offset = -drift; offset <= drift; offset += 1) {
    const timeStep = currentStep + offset;
    // Replay protection: each time step can be used at most once.
    if (timeStep <= lastUsed) continue;

    const expected = generateTotp(secret, timeStep);
    if (constantTimeEqual(code, expected)) {
      return timeStep;
    }
  }

  throw AppError.unauthorized('Invalid TOTP code.');
}

function randomBase32(byteLength: number): string {
  const bytes = new Uint8Array(byteLength);
  crypto.getRandomValues(bytes);
  return base32Encode(bytes);
}

/** 20 random bytes as a padded Base32 secret (32 characters). */
export function generateTotpSecret(): string {
  return randomBase32(TOTP_SECRET_BYTES);
}

/** 20 random bytes as a padded Base32 recovery code. */
export function generateRecoveryCode(): string {
  return randomBase32(RECOVERY_CODE_BYTES);
}

/** Current TOTP time step, exposed for tests and callers that need it. */
export function currentTotpTimeStep(): number {
  return Math.floor(Date.now() / 1000 / TOTP_TIME_STEP_SECONDS);
}
