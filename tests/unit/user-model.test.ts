import { describe, expect, it } from 'vitest';

import { AppError } from '../../src/errors';
import {
  ensureSupportedKdf,
  globMatch,
  KDF_TYPE_ARGON2ID,
  KDF_TYPE_PBKDF2,
} from '../../src/models/user';

function expectBadRequest(fn: () => void, message: string): void {
  try {
    fn();
  } catch (error) {
    expect(error).toBeInstanceOf(AppError);
    expect((error as AppError).status).toBe(400);
    expect((error as AppError).body).toBe(JSON.stringify({ error: message }));
    return;
  }
  throw new Error('expected AppError');
}

describe('globMatch', () => {
  it('supports the ALLOWED_EMAILS patterns', () => {
    expect(globMatch('*@example.com', 'user@example.com')).toBe(true);
    expect(globMatch('*@example.com', 'user@other.com')).toBe(false);
    expect(globMatch('admin@*', 'admin@anything.test')).toBe(true);
    expect(globMatch('a?c', 'abc')).toBe(true);
    expect(globMatch('a?c', 'ac')).toBe(false);
  });

  it('treats regex metacharacters as literals', () => {
    expect(globMatch('a.b', 'a.b')).toBe(true);
    expect(globMatch('a.b', 'axb')).toBe(false);
    expect(globMatch('a+b', 'a+b')).toBe(true);
  });

  it('requires a full match', () => {
    expect(globMatch('user', 'user@example.com')).toBe(false);
  });
});

describe('ensureSupportedKdf', () => {
  it('accepts PBKDF2 at or above 100000 iterations', () => {
    expect(() =>
      ensureSupportedKdf({ kdf: KDF_TYPE_PBKDF2, kdfIterations: 100_000 }),
    ).not.toThrow();
    expect(() =>
      ensureSupportedKdf({ kdf: KDF_TYPE_PBKDF2, kdfIterations: 600_000 }),
    ).not.toThrow();
  });

  it('rejects PBKDF2 below the minimum', () => {
    expectBadRequest(
      () => ensureSupportedKdf({ kdf: KDF_TYPE_PBKDF2, kdfIterations: 99_999 }),
      'PBKDF2 iterations must be at least 100000',
    );
  });

  it('validates the full Argon2id parameter set', () => {
    expect(() =>
      ensureSupportedKdf({
        kdf: KDF_TYPE_ARGON2ID,
        kdfIterations: 3,
        kdfMemory: 64,
        kdfParallelism: 4,
      }),
    ).not.toThrow();

    expectBadRequest(
      () =>
        ensureSupportedKdf({
          kdf: KDF_TYPE_ARGON2ID,
          kdfIterations: 0,
          kdfMemory: 64,
          kdfParallelism: 4,
        }),
      'Argon2 KDF iterations must be at least 1',
    );
    expectBadRequest(
      () => ensureSupportedKdf({ kdf: KDF_TYPE_ARGON2ID, kdfIterations: 3, kdfParallelism: 4 }),
      'Argon2 memory parameter is required',
    );
    expectBadRequest(
      () =>
        ensureSupportedKdf({
          kdf: KDF_TYPE_ARGON2ID,
          kdfIterations: 3,
          kdfMemory: 14,
          kdfParallelism: 4,
        }),
      'Argon2 memory must be between 15 MB and 1024 MB',
    );
    expectBadRequest(
      () => ensureSupportedKdf({ kdf: KDF_TYPE_ARGON2ID, kdfIterations: 3, kdfMemory: 64 }),
      'Argon2 parallelism parameter is required',
    );
    expectBadRequest(
      () =>
        ensureSupportedKdf({
          kdf: KDF_TYPE_ARGON2ID,
          kdfIterations: 3,
          kdfMemory: 64,
          kdfParallelism: 17,
        }),
      'Argon2 parallelism must be between 1 and 16',
    );
  });

  it('rejects unknown KDF types with the exact message', () => {
    expectBadRequest(
      () => ensureSupportedKdf({ kdf: 2, kdfIterations: 600_000 }),
      'Unsupported KDF type. Only PBKDF2 (0) and Argon2id (1) are supported',
    );
  });
});
