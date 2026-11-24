import { jwtVerify, SignJWT } from 'jose';

import type { Env } from '../env';
import { AppError } from '../errors';
import { constantTimeEqual } from './password';

/** Clock skew allowance for `exp`/`nbf`, matching `JWT_VALIDATION_LEEWAY_SECS`. */
export const JWT_LEEWAY_SECONDS = 60;

export const ACCESS_TOKEN_TTL_SECONDS = 3600;
export const REFRESH_TOKEN_TTL_SECONDS = 30 * 24 * 3600;
export const REMEMBER_TOKEN_TTL_SECONDS = 30 * 24 * 3600;
export const SEND_ACCESS_TOKEN_TTL_SECONDS = 120;

export const SEND_ACCESS_ISSUER = 'warden-worker|send-access';
export const REMEMBER_TOKEN_ISSUER = 'warden-worker-device-remember';

/** Access-token claims. Field names are part of the client contract. */
export interface AccessClaims {
  sub: string;
  sstamp: string;
  premium: boolean;
  name: string;
  email: string;
  email_verified: boolean;
  device: string;
  devicetype: string;
  client_id: string;
  scope: string[];
  amr: string[];
  exp: number;
  iat: number;
  nbf: number;
}

export interface RefreshClaims {
  sub: 'password';
  device_token: string;
  sstamp: string;
  exp: number;
  iat: number;
  nbf: number;
}

export interface RememberClaims {
  sub: string;
  user_uuid: string;
  iss: string;
  exp: number;
  iat: number;
  nbf: number;
}

/** Attachment / Send file upload+download claims. */
export interface FileTokenClaims {
  sub: string;
  device: string;
  cipher_id: string;
  attachment_id: string;
  exp: number;
}

export interface SendFileClaims {
  sub: string;
  device: string;
  send_id: string;
  file_id: string;
  exp: number;
}

export interface SendAccessClaims {
  sub: string;
  iss: string;
  exp: number;
  iat: number;
  nbf: number;
}

function signingKey(secret: string): Uint8Array {
  return new TextEncoder().encode(secret);
}

/** Read a required JWT secret; a missing secret is a 500, not a 401. */
export function jwtSecret(env: Env, name: 'JWT_SECRET' | 'JWT_REFRESH_SECRET'): string {
  const value = env[name];
  if (value === undefined || value.length === 0) {
    // Registration does not sign tokens, so a deployment missing the secrets
    // registers fine and then answers every login with an opaque 500. Log the
    // cause: it is a deployment mistake, and the value itself is never printed.
    console.error(
      `[auth] ${name} is not set; refusing to sign tokens. ` +
        `Set it with: wrangler secret put ${name}`,
    );
    throw AppError.internal();
  }
  return value;
}

/** Sign a token with `iat`/`nbf` = now and `exp` = now + ttl (HS256, `alg` only). */
export async function signToken(
  payload: Record<string, unknown>,
  secret: string,
  ttlSeconds: number,
): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  return new SignJWT(payload)
    .setProtectedHeader({ alg: 'HS256' })
    .setIssuedAt(now)
    .setNotBefore(now)
    .setExpirationTime(now + ttlSeconds)
    .sign(signingKey(secret));
}

/** Verify signature, `exp` and (when given) `iss`. Returns null on any failure. */
export async function verifyToken<T>(
  token: string,
  secret: string,
  options: { leewaySeconds?: number; issuer?: string } = {},
): Promise<T | null> {
  try {
    const { payload } = await jwtVerify(token, signingKey(secret), {
      algorithms: ['HS256'],
      clockTolerance: options.leewaySeconds ?? JWT_LEEWAY_SECONDS,
      requiredClaims: ['exp'],
      ...(options.issuer !== undefined ? { issuer: options.issuer } : {}),
    });
    return payload as unknown as T;
  } catch {
    return null;
  }
}

/** Verify an access token and check that every required claim is present. */
export async function verifyAccessToken(env: Env, token: string): Promise<AccessClaims | null> {
  const payload = await verifyToken<Record<string, unknown>>(token, jwtSecret(env, 'JWT_SECRET'));
  if (payload === null) return null;

  const { sub, sstamp, device, email, name, client_id, devicetype } = payload;
  if (
    typeof sub !== 'string' ||
    typeof sstamp !== 'string' ||
    typeof device !== 'string' ||
    typeof email !== 'string' ||
    typeof name !== 'string' ||
    typeof client_id !== 'string' ||
    typeof devicetype !== 'string'
  ) {
    return null;
  }

  return payload as unknown as AccessClaims;
}

/**
 * Parse the `Authorization` header exactly like the Rust implementation:
 * a case-sensitive `"Bearer "` prefix with a single space.
 */
export function parseBearer(headerValue: string | undefined): string | null {
  if (headerValue === undefined) return null;
  if (!headerValue.startsWith('Bearer ')) return null;
  const token = headerValue.slice('Bearer '.length);
  return token.length > 0 ? token : null;
}

/**
 * Re-check the token against the database: the security stamp must match and
 * the device row must still exist. Mirrors `decode_access_token`.
 */
export async function isSessionStillValid(
  db: { prepare(query: string): D1PreparedStatement },
  claims: AccessClaims,
): Promise<boolean> {
  const user = await db
    .prepare('SELECT security_stamp FROM users WHERE id = ?1')
    .bind(claims.sub)
    .first<{ security_stamp: string | null }>();

  if (user === null) return false;
  if (!constantTimeEqual(claims.sstamp, user.security_stamp ?? '')) return false;

  const device = await db
    .prepare('SELECT identifier FROM devices WHERE identifier = ?1 AND user_id = ?2')
    .bind(claims.device, claims.sub)
    .first<{ identifier: string }>();

  return device !== null;
}
