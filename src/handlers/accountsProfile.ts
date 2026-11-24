import type { Context } from 'hono';
import { z } from 'zod';

import { getDb, nowString } from '../db/client';
import { AppError } from '../errors';
import { readJson } from '../http/body';
import { jsonResponse } from '../http/rawJson';
import { buildProfile } from '../models/profile';
import type { UserRow } from '../models/user';
import { publishUserUpdate } from '../notifications/publish';
import type { AppEnv } from '../types';

const profileSchema = z.object({ name: z.string() });
const avatarSchema = z.object({ avatarColor: z.string().nullish() });

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

async function isTwoFactorEnabled(c: Context<AppEnv>, userId: string): Promise<boolean> {
  const row = await getDb(c.env)
    .prepare(
      'SELECT COUNT(*) AS c FROM twofactor WHERE user_uuid = ?1 AND enabled = 1 AND atype = 0',
    )
    .bind(userId)
    .first<{ c: number }>();
  return (row?.c ?? 0) > 0;
}

/** `GET /api/accounts/profile` */
export async function getProfileHandler(c: Context<AppEnv>): Promise<Response> {
  const user = await loadUser(c);
  return jsonResponse(buildProfile(user, await isTwoFactorEnabled(c, user.id)));
}

/** `POST|PUT /api/accounts/profile` */
export async function postProfileHandler(c: Context<AppEnv>): Promise<Response> {
  const payload = await readJson(c.req.raw, profileSchema);
  if (payload.name.length > 50) {
    throw AppError.badRequest('The field Name must be a string with a maximum length of 50.');
  }

  const user = await loadUser(c);
  const now = nowString();

  await getDb(c.env)
    .prepare('UPDATE users SET name = ?1, updated_at = ?2 WHERE id = ?3')
    .bind(payload.name, now, user.id)
    .run();

  publishUserUpdate(c.env, user.id, 10, now, c.get('claims').device);

  return jsonResponse(
    buildProfile(
      { ...user, name: payload.name, updated_at: now },
      await isTwoFactorEnabled(c, user.id),
    ),
  );
}

/** `PUT /api/accounts/avatar` */
export async function putAvatarHandler(c: Context<AppEnv>): Promise<Response> {
  const payload = await readJson(c.req.raw, avatarSchema);
  const color = payload.avatarColor ?? null;

  if (color !== null && color.length !== 7) {
    throw AppError.badRequest(
      'The field AvatarColor must be a HTML/Hex color code with a length of 7 characters',
    );
  }

  const user = await loadUser(c);
  const now = nowString();

  await getDb(c.env)
    .prepare('UPDATE users SET avatar_color = ?1, updated_at = ?2 WHERE id = ?3')
    .bind(color, now, user.id)
    .run();

  return jsonResponse(
    buildProfile(
      { ...user, avatar_color: color, updated_at: now },
      await isTwoFactorEnabled(c, user.id),
    ),
  );
}

/** `GET /api/accounts/revision-date` — millisecond Unix timestamp. */
export async function revisionDateHandler(c: Context<AppEnv>): Promise<Response> {
  const row = await getDb(c.env)
    .prepare('SELECT updated_at FROM users WHERE id = ?1')
    .bind(c.get('claims').sub)
    .first<{ updated_at: string }>();

  const parsed = row === null ? Number.NaN : Date.parse(row.updated_at);
  return jsonResponse(Number.isNaN(parsed) ? Date.now() : parsed);
}

/** `GET /api/tasks` — task workflows are not supported; always empty. */
export function getTasksHandler(): Response {
  return jsonResponse({ data: [], object: 'list' });
}
