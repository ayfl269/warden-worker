import { AppError } from '../errors';

/** User row, mirroring `sql/schema.sql`. */
export interface UserRow {
  id: string;
  name: string | null;
  avatar_color: string | null;
  email: string;
  email_verified: number;
  master_password_hash: string;
  master_password_hint: string | null;
  password_salt: string | null;
  password_iterations: number;
  key: string;
  private_key: string;
  public_key: string;
  kdf_type: number;
  kdf_iterations: number;
  kdf_memory: number | null;
  kdf_parallelism: number | null;
  security_stamp: string | null;
  equivalent_domains: string;
  excluded_globals: string;
  totp_recover: string | null;
  created_at: string;
  updated_at: string;
}

export const KDF_TYPE_PBKDF2 = 0;
export const KDF_TYPE_ARGON2ID = 1;

export const MIN_PBKDF2_ITERATIONS = 100_000;
export const DEFAULT_PBKDF2_ITERATIONS = 600_000;

export interface KdfParams {
  kdf: number;
  kdfIterations: number;
  kdfMemory?: number | null;
  kdfParallelism?: number | null;
}

/** Mirrors `ensure_supported_kdf`, including the exact error strings. */
export function ensureSupportedKdf(kdf: KdfParams): void {
  if (kdf.kdf === KDF_TYPE_PBKDF2) {
    if (!Number.isInteger(kdf.kdfIterations) || kdf.kdfIterations < MIN_PBKDF2_ITERATIONS) {
      throw AppError.badRequest('PBKDF2 iterations must be at least 100000');
    }
    return;
  }

  if (kdf.kdf === KDF_TYPE_ARGON2ID) {
    if (!Number.isInteger(kdf.kdfIterations) || kdf.kdfIterations < 1) {
      throw AppError.badRequest('Argon2 KDF iterations must be at least 1');
    }
    if (kdf.kdfMemory === undefined || kdf.kdfMemory === null) {
      throw AppError.badRequest('Argon2 memory parameter is required');
    }
    if (!Number.isInteger(kdf.kdfMemory) || kdf.kdfMemory < 15 || kdf.kdfMemory > 1024) {
      throw AppError.badRequest('Argon2 memory must be between 15 MB and 1024 MB');
    }
    if (kdf.kdfParallelism === undefined || kdf.kdfParallelism === null) {
      throw AppError.badRequest('Argon2 parallelism parameter is required');
    }
    if (
      !Number.isInteger(kdf.kdfParallelism) ||
      kdf.kdfParallelism < 1 ||
      kdf.kdfParallelism > 16
    ) {
      throw AppError.badRequest('Argon2 parallelism must be between 1 and 16');
    }
    return;
  }

  throw AppError.badRequest('Unsupported KDF type. Only PBKDF2 (0) and Argon2id (1) are supported');
}

/** `glob_match` equivalent: supports `*` and `?`, everything else is literal. */
export function globMatch(pattern: string, value: string): boolean {
  let regex = '';
  for (const char of pattern) {
    if (char === '*') regex += '.*';
    else if (char === '?') regex += '.';
    else regex += char.replace(/[.+^${}()|[\]\\]/g, '\\$&');
  }
  return new RegExp(`^${regex}$`, 's').test(value);
}
