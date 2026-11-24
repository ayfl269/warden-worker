import { AppError } from '../errors';
import type { UserRow } from '../models/user';
import { verifyPassword } from './password';

/**
 * Assert the client-provided master password hash against the stored
 * server-side PBKDF2 hash. Throws 401 `Invalid password` on mismatch.
 */
export function assertMasterPassword(user: UserRow, clientHash: string): void {
  if (
    user.password_salt === null ||
    !verifyPassword(
      clientHash,
      user.master_password_hash,
      user.password_salt,
      user.password_iterations,
    )
  ) {
    throw AppError.unauthorized('Invalid password');
  }
}
