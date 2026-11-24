import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  base32Decode,
  base32Encode,
  currentTotpTimeStep,
  generateRecoveryCode,
  generateTotp,
  generateTotpSecret,
  validateTotp,
} from '../../src/auth/totp';
import { AppError } from '../../src/errors';

/** RFC 6238 test secret: the ASCII string "12345678901234567890". */
const RFC_SECRET_ASCII = '12345678901234567890';
const RFC_SECRET_BASE32 = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';

function stepAt(seconds: number): number {
  return Math.floor(seconds / 30);
}

function expectAppError(fn: () => unknown, status: number, body: string): void {
  try {
    fn();
  } catch (error) {
    expect(error).toBeInstanceOf(AppError);
    expect((error as AppError).status).toBe(status);
    expect((error as AppError).body).toBe(JSON.stringify({ error: body }));
    return;
  }
  throw new Error('expected an AppError');
}

afterEach(() => {
  vi.useRealTimers();
});

describe('base32', () => {
  it('matches the RFC 4648 vector for the RFC 6238 secret', () => {
    const encoded = base32Encode(new TextEncoder().encode(RFC_SECRET_ASCII));
    expect(encoded).toBe(RFC_SECRET_BASE32);
  });

  it('round-trips padded and unpadded input', () => {
    const bytes = new Uint8Array([0x00, 0x01, 0xfb, 0xff, 0x7f]);
    const padded = base32Encode(bytes);
    expect([...base32Decode(padded)]).toEqual([...bytes]);
    expect([...base32Decode(padded.replace(/=+$/, ''))]).toEqual([...bytes]);
  });

  it('rejects invalid characters with a 500 crypto error', () => {
    expectAppError(() => base32Decode('NOT-BASE32!'), 500, 'Crypto error: Invalid Base32 input');
  });
});

describe('generateTotp', () => {
  // RFC 6238 Appendix B, SHA-1, truncated to 6 digits.
  const vectors: ReadonlyArray<readonly [number, string]> = [
    [59, '287082'],
    [1111111109, '081804'],
    [1111111111, '050471'],
    [1234567890, '005924'],
    [2000000000, '279037'],
    [20000000000, '353130'],
  ];

  for (const [seconds, expected] of vectors) {
    it(`matches the RFC 6238 vector at t=${seconds}`, () => {
      expect(generateTotp(RFC_SECRET_BASE32, stepAt(seconds))).toBe(expected);
    });
  }
});

describe('validateTotp', () => {
  it('accepts the current step and returns it', () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date(1_111_111_109 * 1000));

    const step = validateTotp('081804', RFC_SECRET_BASE32, 0, true);
    expect(step).toBe(stepAt(1_111_111_109));
  });

  it('rejects a replayed step', () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date(1_111_111_109 * 1000));

    expectAppError(
      () => validateTotp('081804', RFC_SECRET_BASE32, stepAt(1_111_111_109), true),
      401,
      'Invalid TOTP code.',
    );
  });

  it('accepts the previous step only when drift is allowed', () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date(1_111_111_109 * 1000));
    const previous = generateTotp(RFC_SECRET_BASE32, stepAt(1_111_111_109) - 1);

    expect(validateTotp(previous, RFC_SECRET_BASE32, 0, true)).toBe(stepAt(1_111_111_109) - 1);

    expectAppError(
      () => validateTotp(previous, RFC_SECRET_BASE32, 0, false),
      401,
      'Invalid TOTP code.',
    );
  });

  it('rejects malformed codes with a 400 before doing any crypto', () => {
    expectAppError(
      () => validateTotp('12345', RFC_SECRET_BASE32, 0, true),
      400,
      'Invalid TOTP code format',
    );
    expectAppError(
      () => validateTotp('abcdef', RFC_SECRET_BASE32, 0, true),
      400,
      'Invalid TOTP code format',
    );
  });
});

describe('secret generation', () => {
  it('generates a padded 32-character secret that decodes to 20 bytes', () => {
    const secret = generateTotpSecret();
    expect(secret).toHaveLength(32);
    expect(base32Decode(secret)).toHaveLength(20);
    expect(generateTotpSecret()).not.toBe(secret);
  });

  it('generates a recovery code with the same shape', () => {
    const code = generateRecoveryCode();
    expect(code).toHaveLength(32);
    expect(base32Decode(code)).toHaveLength(20);
  });

  it('reports the current time step', () => {
    expect(currentTotpTimeStep()).toBe(Math.floor(Date.now() / 1000 / 30));
  });
});
