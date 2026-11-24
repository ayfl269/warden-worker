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
