import type { Context } from 'hono';
import { z } from 'zod';
import { generateSalt, hashPasswordForStorage } from '../auth/password';
import { getDb, nowString } from '../db/client';
import { serverPasswordIterations } from '../env';
import { AppError } from '../errors';
import { readJson } from '../http/body';
import { enforceIpRateLimit } from '../http/limits';
import { jsonResponse } from '../http/rawJson';
import {
  DEFAULT_PBKDF2_ITERATIONS,
  ensureSupportedKdf,
  globMatch,
  KDF_TYPE_ARGON2ID,
  KDF_TYPE_PBKDF2,
  type KdfParams,
} from '../models/user';
import type { AppEnv } from '../types';

const kdfSchema = z.object({
  kdfType: z.number(),
  iterations: z.number(),
  memory: z.number().nullish(),
  parallelism: z.number().nullish(),
});

const preloginSchema = z.object({ email: z.string() });

const registerSchema = z.object({
  name: z.string().nullish(),
  email: z.string(),
  masterPasswordHint: z.string().nullish(),
  userAsymmetricKeys: z.object({ publicKey: z.string(), encryptedPrivateKey: z.string() }),
  masterPasswordAuthentication: z
    .object({ kdf: kdfSchema, salt: z.string(), hash: z.string() })
    .optional(),
  masterPasswordUnlock: z.object({ kdf: kdfSchema, salt: z.string(), key: z.string() }).optional(),
  kdf: kdfSchema.optional(),
  key: z.string().optional(),
  masterPasswordHash: z.string().optional(),
});

function toKdfParams(raw: z.infer<typeof kdfSchema>): KdfParams {
  return {
    kdf: raw.kdfType,
    kdfIterations: raw.iterations,
    kdfMemory: raw.memory ?? null,
    kdfParallelism: raw.parallelism ?? null,
  };
}

/** `POST /identity/accounts/prelogin` — note: the email is NOT lowercased. */
export async function preloginHandler(c: Context<AppEnv>): Promise<Response> {
  await enforceIpRateLimit(
    c.env,
    c.req.raw.headers,
    'LOGIN_RATE_LIMITER',
    'prelogin',
    'Too many requests. Please try again later.',
  );

  const payload = await readJson(c.req.raw, preloginSchema);
  const db = getDb(c.env);

  const row = await db
    .prepare(
      'SELECT kdf_type, kdf_iterations, kdf_memory, kdf_parallelism FROM users WHERE email = ?1',
    )
    .bind(payload.email)
    .first<{
      kdf_type: number;
      kdf_iterations: number;
      kdf_memory: number | null;
      kdf_parallelism: number | null;
    }>();

  const kdfType = row?.kdf_type ?? KDF_TYPE_PBKDF2;
  const iterations = row?.kdf_iterations ?? DEFAULT_PBKDF2_ITERATIONS;
  const memory = row?.kdf_memory ?? null;
  const parallelism = row?.kdf_parallelism ?? null;

  return jsonResponse({
    kdf: kdfType,
    kdfIterations: iterations,
    kdfMemory: memory,
    kdfParallelism: parallelism,
    kdfSettings: {
      iterations,
      kdfType,
      memory,
      parallelism,
    },
    salt: null,
  });
}

/** `POST /identity/accounts/register` (+ `/finish`) */
export async function registerHandler(c: Context<AppEnv>): Promise<Response> {
  await enforceIpRateLimit(
    c.env,
    c.req.raw.headers,
    'LOGIN_RATE_LIMITER',
    'register',
    'Too many requests. Please try again later.',
  );

  const payload = await readJson(c.req.raw, registerSchema);

  const normalizedEmail = payload.email.trim().toLowerCase();
  const current = payload.masterPasswordAuthentication;
  const unlock = payload.masterPasswordUnlock;

  let kdf: KdfParams;
  let clientHash: string;
  let userKey: string;

  if (current !== undefined && unlock !== undefined) {
    const authKdf = toKdfParams(current.kdf);
    const unlockKdf = toKdfParams(unlock.kdf);
    const sameKdf =
      authKdf.kdf === unlockKdf.kdf &&
      authKdf.kdfIterations === unlockKdf.kdfIterations &&
      (authKdf.kdfMemory ?? null) === (unlockKdf.kdfMemory ?? null) &&
      (authKdf.kdfParallelism ?? null) === (unlockKdf.kdfParallelism ?? null);

    if (!sameKdf || current.salt !== normalizedEmail || unlock.salt !== normalizedEmail) {
      throw AppError.apiJson(422, { error: 'Unexpected RegisterData format' });
    }

    kdf = authKdf;
    clientHash = current.hash;
    userKey = unlock.key;
  } else if (
    payload.kdf !== undefined &&
    payload.key !== undefined &&
    payload.masterPasswordHash !== undefined
  ) {
    kdf = toKdfParams(payload.kdf);
    clientHash = payload.masterPasswordHash;
    userKey = payload.key;
  } else {
    throw AppError.apiJson(422, { error: 'Unexpected RegisterData format' });
  }

  const allowedEmails = c.env.ALLOWED_EMAILS;
  if (allowedEmails === undefined || allowedEmails.length === 0) {
    throw AppError.internal();
  }
  if (!allowedEmails.split(',').some((pattern) => globMatch(pattern.trim(), payload.email))) {
    throw AppError.unauthorized('Not allowed to signup');
  }

  ensureSupportedKdf(kdf);

  const passwordSalt = generateSalt();
  const passwordIterations = serverPasswordIterations(c.env);
  const hashedPassword = hashPasswordForStorage(clientHash, passwordSalt, passwordIterations);
  const now = nowString();
  const id = crypto.randomUUID();
  const isArgon2 = kdf.kdf === KDF_TYPE_ARGON2ID;

  const db = getDb(c.env);
  try {
    await db
      .prepare(
        `INSERT INTO users (
           id, name, avatar_color, email, email_verified,
           master_password_hash, master_password_hint, password_salt, password_iterations,
           key, private_key, public_key,
           kdf_type, kdf_iterations, kdf_memory, kdf_parallelism,
           security_stamp, equivalent_domains, excluded_globals, totp_recover,
           created_at, updated_at
         ) VALUES (?1, ?2, NULL, ?3, 0, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, '[]', '[]', NULL, ?16, ?16)`,
      )
      .bind(
        id,
        payload.name ?? null,
        normalizedEmail,
        hashedPassword,
        payload.masterPasswordHint ?? null,
        passwordSalt,
        passwordIterations,
        userKey,
        payload.userAsymmetricKeys.encryptedPrivateKey,
        payload.userAsymmetricKeys.publicKey,
        kdf.kdf,
        kdf.kdfIterations,
        isArgon2 ? (kdf.kdfMemory ?? null) : null,
        isArgon2 ? (kdf.kdfParallelism ?? null) : null,
        crypto.randomUUID(),
        now,
      )
      .run();
  } catch (error) {
    throw AppError.worker(error);
  }

  return jsonResponse({});
}
