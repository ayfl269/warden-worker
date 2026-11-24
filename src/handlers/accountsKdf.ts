import type { Context } from 'hono';
import { z } from 'zod';

import { generateSalt, hashPasswordForStorage } from '../auth/password';
import { assertMasterPassword } from '../auth/verify';
import { getDb, nowString } from '../db/client';
import { serverPasswordIterations } from '../env';
import { AppError } from '../errors';
import { readJson } from '../http/body';
import { jsonResponse } from '../http/rawJson';
import {
  ensureSupportedKdf,
  KDF_TYPE_ARGON2ID,
  type KdfParams,
  type UserRow,
} from '../models/user';
import { publishUserLogout } from '../notifications/publish';
import type { AppEnv } from '../types';

/**
 * `KdfParams` accepts both spellings used by Bitwarden clients:
 * `kdf`/`kdfType`, `kdfIterations`/`iterations`, and the memory/parallelism pair.
 */
const kdfSchema = z
  .object({
    kdf: z.number().optional(),
    kdfType: z.number().optional(),
    kdfIterations: z.number().optional(),
    iterations: z.number().optional(),
    kdfMemory: z.number().nullish(),
    memory: z.number().nullish(),
    kdfParallelism: z.number().nullish(),
    parallelism: z.number().nullish(),
  })
  .refine(
    (value) =>
      (value.kdf ?? value.kdfType) !== undefined &&
      (value.kdfIterations ?? value.iterations) !== undefined,
    { message: 'kdf settings are incomplete' },
  );

const changeKdfSchema = z.object({
  masterPasswordHash: z.string(),
  authenticationData: z.object({
    salt: z.string(),
    kdf: kdfSchema,
    masterPasswordAuthenticationHash: z.string(),
  }),
  unlockData: z.object({
    salt: z.string(),
    kdf: kdfSchema,
    masterKeyWrappedUserKey: z.string(),
  }),
});

type RawKdf = z.infer<typeof kdfSchema>;

function resolveKdf(raw: RawKdf): KdfParams {
  return {
    kdf: raw.kdf ?? raw.kdfType ?? 0,
    kdfIterations: raw.kdfIterations ?? raw.iterations ?? 0,
    kdfMemory: raw.kdfMemory ?? raw.memory ?? null,
    kdfParallelism: raw.kdfParallelism ?? raw.parallelism ?? null,
  };
}

function kdfEquals(left: KdfParams, right: KdfParams): boolean {
  return (
    left.kdf === right.kdf &&
    left.kdfIterations === right.kdfIterations &&
    (left.kdfMemory ?? null) === (right.kdfMemory ?? null) &&
    (left.kdfParallelism ?? null) === (right.kdfParallelism ?? null)
  );
}

/** `POST /api/accounts/kdf` — change the client-side KDF settings. */
export async function postKdfHandler(c: Context<AppEnv>): Promise<Response> {
  const payload = await readJson(c.req.raw, changeKdfSchema);
  const db = getDb(c.env);

  const user = await db
    .prepare('SELECT * FROM users WHERE id = ?1')
    .bind(c.get('claims').sub)
    .first<UserRow>();
  if (user === null) throw AppError.notFound('User not found');

  assertMasterPassword(user, payload.masterPasswordHash);

  const authKdf = resolveKdf(payload.authenticationData.kdf);
  const unlockKdf = resolveKdf(payload.unlockData.kdf);

  if (!kdfEquals(authKdf, unlockKdf)) {
    throw AppError.badRequest('KDF settings must be equal for authentication and unlock');
  }
  if (user.email !== payload.authenticationData.salt || user.email !== payload.unlockData.salt) {
    throw AppError.badRequest('Invalid master password salt');
  }

  ensureSupportedKdf(unlockKdf);

  const newSalt = generateSalt();
  const passwordIterations = serverPasswordIterations(c.env);
  const newHash = hashPasswordForStorage(
    payload.authenticationData.masterPasswordAuthenticationHash,
    newSalt,
    passwordIterations,
  );

  const isArgon2 = unlockKdf.kdf === KDF_TYPE_ARGON2ID;
  const now = nowString();

  await db
    .prepare(
      `UPDATE users
          SET master_password_hash = ?1, password_salt = ?2, password_iterations = ?3,
              key = ?4, kdf_type = ?5, kdf_iterations = ?6,
              kdf_memory = ?7, kdf_parallelism = ?8,
              security_stamp = ?9, updated_at = ?10
        WHERE id = ?11`,
    )
    .bind(
      newHash,
      newSalt,
      passwordIterations,
      payload.unlockData.masterKeyWrappedUserKey,
      unlockKdf.kdf,
      unlockKdf.kdfIterations,
      isArgon2 ? (unlockKdf.kdfMemory ?? null) : null,
      isArgon2 ? (unlockKdf.kdfParallelism ?? null) : null,
      crypto.randomUUID(),
      now,
      user.id,
    )
    .run();

  publishUserLogout(c.env, user.id, now, c.get('claims').device);

  return jsonResponse({});
}
