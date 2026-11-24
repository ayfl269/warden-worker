import type { Env } from '../env';
import { AppError } from '../errors';

/** Rate limiter bindings known to the application. */
export type RateLimiterBinding = 'LOGIN_RATE_LIMITER' | 'SEND_ACCESS_RATE_LIMITER';

/**
 * Enforce a rate limit.
 *
 * Matches the Rust helper exactly: a missing binding or a failing `limit()`
 * call is fail-open; only `success === false` rejects the request.
 */
export async function enforceRateLimit(
  env: Env,
  binding: RateLimiterBinding,
  key: string,
  errorMessage: string,
): Promise<void> {
  const limiter = env[binding];
  if (limiter === undefined) return;

  let success: boolean;
  try {
    const outcome = await limiter.limit({ key });
    success = outcome.success;
  } catch (error) {
    console.warn(`Rate limiter '${binding}' failed, allowing request`, error);
    return;
  }

  if (!success) {
    throw AppError.tooManyRequests(errorMessage);
  }
}

export async function enforceIpRateLimit(
  env: Env,
  headers: Headers,
  binding: RateLimiterBinding,
  keyPrefix: string,
  errorMessage: string,
): Promise<void> {
  await enforceRateLimit(
    env,
    binding,
    `${keyPrefix}:${requestIpFromHeaders(headers)}`,
    errorMessage,
  );
}

/** Client IP, mirroring `client_context.rs` (missing header → `"unknown"`). */
export function requestIpFromHeaders(headers: Headers): string {
  const value = headers.get('cf-connecting-ip');
  return value !== null && value.length > 0 ? value : 'unknown';
}

/**
 * Throttle an authenticated master-password re-check.
 *
 * Login is rate limited, but the endpoints that re-verify the master password
 * for an already-authenticated session (change password, change KDF, rotate
 * keys, purge vault, delete account) were not. With a stolen access token those
 * turn into an unthrottled password oracle, and each attempt costs a 600k
 * iteration PBKDF2 inside the Durable Object.
 *
 * Keyed by user id rather than IP so a shared NAT does not throttle unrelated
 * accounts.
 */
export async function enforcePasswordVerifyLimit(env: Env, userId: string): Promise<void> {
  await enforceRateLimit(
    env,
    'LOGIN_RATE_LIMITER',
    `verify:${userId}`,
    'Too many password attempts. Please try again later.',
  );
}
