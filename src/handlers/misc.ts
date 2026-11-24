import type { Context } from 'hono';
import { z } from 'zod';

import { getDb } from '../db/client';
import { AppError } from '../errors';
import { readJson } from '../http/body';
import { enforceIpRateLimit } from '../http/limits';
import { jsonResponse } from '../http/rawJson';
import type { AppEnv } from '../types';

/**
 * Small endpoints that exist only for client compatibility.
 */

/** `POST /identity/accounts/register/send-verification-email` — always mocked. */
export function sendVerificationEmailHandler(): Response {
  return jsonResponse('fixed-token-to-mock');
}

const passwordHintSchema = z.object({ email: z.string() });

/**
 * `POST /api/accounts/password-hint`
 *
 * Email delivery is not implemented, so the hint is returned in the error
 * message (matching the Rust implementation).
 */
export async function passwordHintHandler(c: Context<AppEnv>): Promise<Response> {
  await enforceIpRateLimit(
    c.env,
    c.req.raw.headers,
    'LOGIN_RATE_LIMITER',
    'password-hint',
    'Too many requests. Please try again later.',
  );

  const payload = await readJson(c.req.raw, passwordHintSchema);
  const row = await getDb(c.env)
    .prepare('SELECT master_password_hint FROM users WHERE email = ?1')
    .bind(payload.email.toLowerCase())
    .first<{ master_password_hint: string | null }>();

  const hint = row?.master_password_hint?.trim();

  // Bitwarden emails the hint and answers 200 with an empty body. There is no
  // mail delivery here, so returning the hint in the response would hand any
  // anonymous caller a hint for every address they know — and users routinely
  // put the password itself (or a one-step clue) in it. Default to the empty
  // 200; operators who rely on reading the hint can opt in.
  if (c.env.EXPOSE_PASSWORD_HINTS !== '1') {
    return jsonResponse({});
  }

  if (hint === undefined || hint.length === 0) {
    throw AppError.badRequest('Sorry, you have no password hint...');
  }

  throw AppError.badRequest(`Your password hint is: ${hint}`);
}

/** Emergency access is not supported; both endpoints return an empty list. */
export function emptyListHandler(): Response {
  return jsonResponse({ data: [], object: 'list', continuationToken: null });
}

/** WebAuthn/passkeys are not supported; return an empty list. */
export function emptyWebauthnListHandler(): Response {
  return jsonResponse({ object: 'list', data: [], continuationToken: null });
}
