import type { Context } from 'hono';
import { z } from 'zod';
import {
  base32Decode,
  currentTotpTimeStep,
  generateRecoveryCode,
  generateTotpSecret,
  validateTotp,
} from '../auth/totp';
import { assertMasterPassword } from '../auth/verify';
import { getDb, nowString } from '../db/client';
import { allowTotpDrift } from '../env';
import { AppError } from '../errors';
import { readJson } from '../http/body';
import { jsonResponse } from '../http/rawJson';
import type { UserRow } from '../models/user';
import type { AppEnv } from '../types';

/** `TwoFactorType`: 0 = Authenticator (TOTP), 5 = Remember, 8 = RecoveryCode. */
const TYPE_AUTHENTICATOR = 0;
const TYPE_REMEMBER = 5;
const TYPE_RECOVERY_CODE = 8;

const TOTP_KEY_BYTES = 20;

const passwordOrOtpSchema = z.object({
  masterPasswordHash: z.string().nullish(),
  otp: z.string().nullish(),
});

const activateSchema = z.object({
  masterPasswordHash: z.string(),
  key: z.string(),
  token: z.string(),
  otp: z.string().nullish(),
});

const disableSchema = z.object({
  masterPasswordHash: z.string(),
  type: z.number(),
});

const deleteAuthenticatorSchema = z.object({
  masterPasswordHash: z.string(),
  key: z.string(),
  type: z.number(),
});

interface TwoFactorRow {
  uuid: string;
  atype: number;
  enabled: number;
  data: string;
  last_used: number;
}

async function loadUser(c: Context<AppEnv>): Promise<UserRow> {
  const user = await getDb(c.env)
    .prepare('SELECT * FROM users WHERE id = ?1')
    .bind(c.get('claims').sub)
    .first<UserRow>();
  if (user === null) throw AppError.notFound('User not found');
  return user;
}

async function listTwoFactors(c: Context<AppEnv>, userId: string): Promise<TwoFactorRow[]> {
  const result = await getDb(c.env)
    .prepare('SELECT uuid, atype, enabled, data, last_used FROM twofactor WHERE user_uuid = ?1')
    .bind(userId)
    .all<TwoFactorRow>();
  return result.results ?? [];
}

function authenticate(
  c: Context<AppEnv>,
  user: UserRow,
  clientHash: string | null | undefined,
): void {
  if (clientHash === undefined || clientHash === null) {
    throw AppError.badRequest('Missing master password hash');
  }
  assertMasterPassword(user, clientHash);
}

function authenticatorBody(key: string, enabled: boolean): Record<string, unknown> {
  return { enabled, key, object: 'twoFactorAuthenticator' };
}

/** `GET /api/two-factor` */
export async function getTwoFactorHandler(c: Context<AppEnv>): Promise<Response> {
  const rows = await listTwoFactors(c, c.get('claims').sub);
  return jsonResponse({
    data: rows.map((row) => ({
      enabled: row.enabled === 1,
      type: row.atype,
      object: 'twoFactorProvider',
    })),
    object: 'list',
    continuationToken: null,
  });
}

/** `POST /api/two-factor/get-authenticator` */
export async function getAuthenticatorHandler(c: Context<AppEnv>): Promise<Response> {
  const payload = await readJson(c.req.raw, passwordOrOtpSchema);
  const user = await loadUser(c);
  authenticate(c, user, payload.masterPasswordHash);

  const existing = (await listTwoFactors(c, user.id)).find(
    (row) => row.atype === TYPE_AUTHENTICATOR,
  );
  // When nothing is configured yet a fresh, unpersisted key is returned.
  return jsonResponse(
    authenticatorBody(existing?.data ?? generateTotpSecret(), existing !== undefined),
  );
}

/** `POST|PUT /api/two-factor/authenticator` — enable TOTP. */
export async function activateAuthenticatorHandler(c: Context<AppEnv>): Promise<Response> {
  const payload = await readJson(c.req.raw, activateSchema);
  const user = await loadUser(c);
  authenticate(c, user, payload.masterPasswordHash);

  const key = payload.key.toUpperCase();
  let decoded: Uint8Array;
  try {
    decoded = base32Decode(key);
  } catch {
    throw AppError.badRequest('Invalid key length');
  }
  if (decoded.length !== TOTP_KEY_BYTES) {
    throw AppError.badRequest('Invalid key length');
  }

  const existing = (await listTwoFactors(c, user.id)).find(
    (row) => row.atype === TYPE_AUTHENTICATOR,
  );
  const step = validateTotp(payload.token, key, existing?.last_used ?? 0, allowTotpDrift(c.env));
  const now = nowString();
  const db = getDb(c.env);

  await db
    .prepare('DELETE FROM twofactor WHERE user_uuid = ?1 AND atype IN (?2, ?3)')
    .bind(user.id, TYPE_AUTHENTICATOR, TYPE_REMEMBER)
    .run();
  await db
    .prepare(
      'INSERT INTO twofactor (uuid, user_uuid, atype, enabled, data, last_used) VALUES (?1, ?2, ?3, 1, ?4, ?5)',
    )
    .bind(crypto.randomUUID(), user.id, TYPE_AUTHENTICATOR, key, step)
    .run();

  if (user.totp_recover === null) {
    await db
      .prepare('UPDATE users SET totp_recover = ?1, updated_at = ?2 WHERE id = ?3')
      .bind(generateRecoveryCode(), now, user.id)
      .run();
  }

  return jsonResponse(authenticatorBody(key, true));
}

/** `POST|PUT /api/two-factor/disable` */
export async function disableTwoFactorHandler(c: Context<AppEnv>): Promise<Response> {
  const payload = await readJson(c.req.raw, disableSchema);
  const user = await loadUser(c);
  authenticate(c, user, payload.masterPasswordHash);

  const db = getDb(c.env);
  await db
    .prepare('DELETE FROM twofactor WHERE user_uuid = ?1 AND atype = ?2')
    .bind(user.id, payload.type)
    .run();

  const remaining = (await listTwoFactors(c, user.id)).filter(
    (row) => row.atype < 1000 && row.atype !== TYPE_REMEMBER,
  );
  if (remaining.length === 0) {
    await db.prepare('UPDATE users SET totp_recover = NULL WHERE id = ?1').bind(user.id).run();
  }

  return jsonResponse({ enabled: false, type: payload.type, object: 'twoFactorProvider' });
}

/** `DELETE /api/two-factor/authenticator` */
export async function deleteAuthenticatorHandler(c: Context<AppEnv>): Promise<Response> {
  const payload = await readJson(c.req.raw, deleteAuthenticatorSchema);
  if (payload.type !== TYPE_AUTHENTICATOR) {
    throw AppError.badRequest('Invalid two factor type');
  }

  const user = await loadUser(c);
  authenticate(c, user, payload.masterPasswordHash);

  const existing = (await listTwoFactors(c, user.id)).find(
    (row) => row.atype === TYPE_AUTHENTICATOR,
  );
  if (existing === undefined) {
    throw AppError.badRequest('TOTP not configured');
  }
  if (existing.data !== payload.key.toUpperCase()) {
    throw AppError.badRequest('TOTP key does not match recorded value');
  }

  await getDb(c.env).prepare('DELETE FROM twofactor WHERE uuid = ?1').bind(existing.uuid).run();

  return jsonResponse({ enabled: false, type: payload.type, object: 'twoFactorProvider' });
}

/** `POST /api/two-factor/get-recover` */
export async function getRecoverHandler(c: Context<AppEnv>): Promise<Response> {
  const payload = await readJson(c.req.raw, passwordOrOtpSchema);
  const user = await loadUser(c);
  authenticate(c, user, payload.masterPasswordHash);

  return jsonResponse({ code: user.totp_recover, object: 'twoFactorRecover' });
}

/** Exposed for the login flow: whether TOTP is enabled for a user. */
export async function totpEnabledForUser(c: Context<AppEnv>, userId: string): Promise<boolean> {
  const rows = await listTwoFactors(c, userId);
  return rows.some((row) => row.enabled === 1 && row.atype === TYPE_AUTHENTICATOR);
}

export { currentTotpTimeStep, TYPE_AUTHENTICATOR, TYPE_RECOVERY_CODE, TYPE_REMEMBER };
