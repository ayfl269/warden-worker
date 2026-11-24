import type { MiddlewareHandler } from 'hono';

import { getDbUnconstrained } from '../db/client';
import { AppError } from '../errors';
import type { AppEnv } from '../types';
import { isSessionStillValid, parseBearer, verifyAccessToken } from './jwt';

/**
 * Bearer-token authentication.
 *
 * Validation order matches `src/auth.rs`:
 *   1. header must start with `Bearer `
 *   2. signature / exp / nbf (60s leeway)
 *   3. `security_stamp` must still match the user row
 *   4. the device row referenced by the token must still exist
 *
 * Steps 1–4 all collapse to the same 401 messages as the Rust implementation.
 */
export function requireAuth(): MiddlewareHandler<AppEnv> {
  return async (c, next) => {
    const token = parseBearer(c.req.header('authorization'));
    if (token === null) {
      throw AppError.unauthorized('Missing or invalid token');
    }

    const claims = await verifyAccessToken(c.env, token);
    if (claims === null) {
      throw AppError.unauthorized('Invalid token');
    }

    const db = getDbUnconstrained(c.env);
    let valid: boolean;
    try {
      valid = await isSessionStillValid(db, claims);
    } catch {
      throw AppError.database();
    }

    if (!valid) {
      throw AppError.unauthorized('Invalid token');
    }

    c.set('claims', claims);
    await next();
  };
}
