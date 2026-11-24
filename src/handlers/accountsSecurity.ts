import type { Context } from 'hono';
import { z } from 'zod';

import { generateSalt, hashPasswordForStorage, verifyPassword } from '../auth/password';
import { getDb, nowString } from '../db/client';
import { deleteUserDevices } from '../db/devices';
import { serverPasswordIterations } from '../env';
import { AppError } from '../errors';
import { readJson } from '../http/body';
import { jsonResponse } from '../http/rawJson';
import type { UserRow } from '../models/user';
import { publishUserLogout } from '../notifications/publish';
import type { AppEnv } from '../types';

const passwordSchema = z.object({
  masterPasswordHash: z.string(),
  newMasterPasswordHash: z.string(),
  masterPasswordHint: z.string().nullish(),
  key: z.string(),
});

const passwordOrOtpSchema = z.object({
  masterPasswordHash: z.string().nullish(),
  otp: z.string().nullish(),
});

const deleteSchema = z.object({ masterPasswordHash: z.string().nullish() });

async function loadUser(c: Context<AppEnv>): Promise<UserRow> {
  const user = await getDb(c.env)
    .prepare('SELECT * FROM users WHERE id = ?1')
    .bind(c.get('claims').sub)
    .first<UserRow>();
  if (user === null) {
    throw AppError.notFound('User not found');
  }
  return user;
}

function assertPassword(user: UserRow, clientHash: string): void {
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

/** `POST /api/accounts/password` — rotate the master password. */
export async function postPasswordHandler(c: Context<AppEnv>): Promise<Response> {
  const payload = await readJson(c.req.raw, passwordSchema);
  const user = await loadUser(c);
  assertPassword(user, payload.masterPasswordHash);

  const salt = generateSalt();
  const iterations = serverPasswordIterations(c.env);
  const hash = hashPasswordForStorage(payload.newMasterPasswordHash, salt, iterations);
  const now = nowString();
  const stamp = crypto.randomUUID();

  await getDb(c.env)
    .prepare(
      `UPDATE users
          SET master_password_hash = ?1, password_salt = ?2, password_iterations = ?3,
              key = ?4, master_password_hint = ?5, security_stamp = ?6, updated_at = ?7
        WHERE id = ?8`,
    )
    .bind(
      hash,
      salt,
      iterations,
      payload.key,
      payload.masterPasswordHint ?? null,
      stamp,
      now,
      user.id,
    )
    .run();

  publishUserLogout(c.env, user.id, now, c.get('claims').device);

  return jsonResponse({});
}

/** `POST /api/accounts/security-stamp` — log out every session. */
export async function postSecurityStampHandler(c: Context<AppEnv>): Promise<Response> {
  const payload = await readJson(c.req.raw, passwordOrOtpSchema);
  if (payload.masterPasswordHash === undefined || payload.masterPasswordHash === null) {
    throw AppError.badRequest('Missing master password hash');
  }

  const user = await loadUser(c);
  assertPassword(user, payload.masterPasswordHash);

  const db = getDb(c.env);
  const now = nowString();
  await deleteUserDevices(db, user.id);
  await db
    .prepare('UPDATE users SET security_stamp = ?1, updated_at = ?2 WHERE id = ?3')
    .bind(crypto.randomUUID(), now, user.id)
    .run();

  publishUserLogout(c.env, user.id, now);

  return jsonResponse({});
}

/** `DELETE /api/accounts` and `POST /api/accounts/delete`. */
export async function deleteAccountHandler(c: Context<AppEnv>): Promise<Response> {
  const payload = await readJson(c.req.raw, deleteSchema);
  if (payload.masterPasswordHash === undefined || payload.masterPasswordHash === null) {
    throw AppError.badRequest('Missing master password hash');
  }

  const user = await loadUser(c);
  assertPassword(user, payload.masterPasswordHash);

  const db = getDb(c.env);
  await db.batch([
    db.prepare('DELETE FROM ciphers WHERE user_id = ?1').bind(user.id),
    db.prepare('DELETE FROM folders WHERE user_id = ?1').bind(user.id),
    db.prepare('DELETE FROM sends WHERE user_id = ?1').bind(user.id),
    db.prepare('DELETE FROM sends_pending WHERE user_id = ?1').bind(user.id),
    db.prepare('DELETE FROM devices WHERE user_id = ?1').bind(user.id),
    db.prepare('DELETE FROM twofactor WHERE user_uuid = ?1').bind(user.id),
    db.prepare('DELETE FROM auth_requests WHERE user_id = ?1').bind(user.id),
    db.prepare('DELETE FROM users WHERE id = ?1').bind(user.id),
  ]);

  return jsonResponse({});
}
