import type { Context } from 'hono';
import { z } from 'zod';

import { generateSalt, hashPasswordForStorage } from '../auth/password';
import { assertMasterPassword } from '../auth/verify';
import { executeInBatches, getDb, nowString } from '../db/client';
import { getEnvUsize, serverPasswordIterations } from '../env';
import { AppError } from '../errors';
import { readJson } from '../http/body';
import { jsonResponse } from '../http/rawJson';
import { buildCipherData, cipherRequestSchema, typeFieldsOf } from '../models/cipher';
import {
  ensureSupportedKdf,
  KDF_TYPE_ARGON2ID,
  type KdfParams,
  type UserRow,
} from '../models/user';
import { publishUserLogout } from '../notifications/publish';
import type { AppEnv } from '../types';

const rotationSchema = z.object({
  accountUnlockData: z.object({
    masterPasswordUnlockData: z.object({
      kdfType: z.number(),
      kdfIterations: z.number(),
      kdfParallelism: z.number().nullish(),
      kdfMemory: z.number().nullish(),
      email: z.string(),
      masterKeyAuthenticationHash: z.string(),
      masterKeyEncryptedUserKey: z.string(),
    }),
  }),
  accountKeys: z.object({
    userKeyEncryptedAccountPrivateKey: z.string(),
    accountPublicKey: z.string(),
  }),
  accountData: z.object({
    ciphers: z.array(z.unknown()),
    folders: z.array(z.object({ id: z.string().nullish(), name: z.string() })),
    sends: z.array(z.unknown()).nullish(),
  }),
  oldMasterKeyAuthenticationHash: z.string(),
});

/** `POST /api/accounts/key-management/rotate-user-account-keys` */
export async function rotateUserKeysHandler(c: Context<AppEnv>): Promise<Response> {
  const payload = await readJson(c.req.raw, rotationSchema);
  const db = getDb(c.env);
  const claims = c.get('claims');
  const batchSize = getEnvUsize(c.env, 'IMPORT_BATCH_SIZE', 30);

  const user = await db
    .prepare('SELECT * FROM users WHERE id = ?1')
    .bind(claims.sub)
    .first<UserRow>();
  if (user === null) throw AppError.notFound('User not found');

  assertMasterPassword(user, payload.oldMasterKeyAuthenticationHash);

  const unlock = payload.accountUnlockData.masterPasswordUnlockData;

  // Metadata must not change during a rotation.
  if (
    unlock.email !== user.email ||
    unlock.kdfType !== user.kdf_type ||
    unlock.kdfIterations !== user.kdf_iterations ||
    (unlock.kdfMemory ?? null) !== (user.kdf_memory ?? null) ||
    (unlock.kdfParallelism ?? null) !== (user.kdf_parallelism ?? null)
  ) {
    throw AppError.badRequest(
      'Changing the kdf variant or email is not supported during key rotation',
    );
  }
  if (payload.accountKeys.accountPublicKey !== user.public_key) {
    throw AppError.badRequest(
      'Changing the asymmetric keypair is not supported during key rotation',
    );
  }

  const kdf: KdfParams = {
    kdf: unlock.kdfType,
    kdfIterations: unlock.kdfIterations,
    kdfMemory: unlock.kdfMemory ?? null,
    kdfParallelism: unlock.kdfParallelism ?? null,
  };
  ensureSupportedKdf(kdf);

  // ── integrity checks ──────────────────────────────────────────────
  const personalCiphers = payload.accountData.ciphers
    .map((raw) => {
      const parsed = cipherRequestSchema.safeParse(raw);
      if (!parsed.success) {
        throw AppError.jsonData(
          parsed.error.issues
            .map((issue) => `${issue.path.map(String).join('.')}: ${issue.message}`)
            .join(', '),
        );
      }
      return parsed.data;
    })
    .filter((cipher) => (cipher.organizationId ?? cipher.organizationID ?? null) === null);

  const requestCipherIds = personalCiphers
    .map((cipher) => cipher.id)
    .filter((id): id is string => id !== undefined && id !== null);
  if (requestCipherIds.length !== personalCiphers.length) {
    throw AppError.badRequest('All ciphers must have an id for key rotation');
  }

  const requestFolderIds = payload.accountData.folders
    .map((folder) => folder.id)
    .filter((id): id is string => id !== undefined && id !== null);

  const dbCiphers = await db
    .prepare('SELECT id FROM ciphers WHERE user_id = ?1 AND organization_id IS NULL')
    .bind(user.id)
    .all<{ id: string }>();
  const dbFolders = await db
    .prepare('SELECT id FROM folders WHERE user_id = ?1')
    .bind(user.id)
    .all<{ id: string }>();

  const dbCipherIds = new Set((dbCiphers.results ?? []).map((row) => row.id));
  const dbFolderIds = new Set((dbFolders.results ?? []).map((row) => row.id));
  const requestCipherIdSet = new Set(requestCipherIds);
  const requestFolderIdSet = new Set(requestFolderIds);

  const missingFromRequest =
    dbCipherIds.size !== requestCipherIdSet.size ||
    dbFolderIds.size !== requestFolderIdSet.size ||
    [...dbCipherIds].some((id) => !requestCipherIdSet.has(id)) ||
    [...dbFolderIds].some((id) => !requestFolderIdSet.has(id));

  if (missingFromRequest) {
    throw AppError.badRequest('All existing ciphers and folders must be included in the rotation');
  }

  // ── rewrites ──────────────────────────────────────────────────────
  const now = nowString();

  const folderStatements: D1PreparedStatement[] = [];
  for (const folder of payload.accountData.folders) {
    if (folder.id === undefined || folder.id === null) continue;
    folderStatements.push(
      db
        .prepare('UPDATE folders SET name = ?1, updated_at = ?2 WHERE id = ?3 AND user_id = ?4')
        .bind(folder.name, now, folder.id, user.id),
    );
  }

  const cipherStatements: D1PreparedStatement[] = [];
  const attachmentStatements: D1PreparedStatement[] = [];

  for (const cipher of personalCiphers) {
    const cipherId = cipher.id as string;
    const data = JSON.stringify(
      buildCipherData({
        name: cipher.name,
        notes: cipher.notes,
        typeFields: typeFieldsOf(cipher),
      }),
    );

    cipherStatements.push(
      db
        .prepare(
          'UPDATE ciphers SET data = ?1, folder_id = ?2, favorite = ?3, updated_at = ?4 WHERE id = ?5 AND user_id = ?6',
        )
        .bind(data, cipher.folderId ?? null, cipher.favorite ? 1 : 0, now, cipherId, user.id),
    );

    for (const [attachmentId, attachment] of Object.entries(cipher.attachments2 ?? {})) {
      attachmentStatements.push(
        db
          .prepare(
            'UPDATE attachments SET file_name = ?1, akey = ?2, updated_at = ?3 WHERE id = ?4 AND cipher_id = ?5',
          )
          .bind(attachment.fileName, attachment.key, now, attachmentId, cipherId),
      );
    }
  }

  await executeInBatches(db, folderStatements, batchSize);
  await executeInBatches(db, cipherStatements, batchSize);
  await executeInBatches(db, attachmentStatements, batchSize);

  // TODO(P4): rotate file Sends (`accountData.sends`) once the Send model lands.

  // ── new credentials ───────────────────────────────────────────────
  const salt = generateSalt();
  const iterations = serverPasswordIterations(c.env);
  const hash = hashPasswordForStorage(unlock.masterKeyAuthenticationHash, salt, iterations);
  const isArgon2 = unlock.kdfType === KDF_TYPE_ARGON2ID;

  await db
    .prepare(
      `UPDATE users
          SET master_password_hash = ?1, password_salt = ?2, password_iterations = ?3,
              key = ?4, private_key = ?5,
              kdf_type = ?6, kdf_iterations = ?7, kdf_memory = ?8, kdf_parallelism = ?9,
              security_stamp = ?10, updated_at = ?11
        WHERE id = ?12`,
    )
    .bind(
      hash,
      salt,
      iterations,
      unlock.masterKeyEncryptedUserKey,
      payload.accountKeys.userKeyEncryptedAccountPrivateKey,
      unlock.kdfType,
      unlock.kdfIterations,
      isArgon2 ? (unlock.kdfMemory ?? null) : null,
      isArgon2 ? (unlock.kdfParallelism ?? null) : null,
      crypto.randomUUID(),
      now,
      user.id,
    )
    .run();

  publishUserLogout(c.env, user.id, now, claims.device);

  return jsonResponse({});
}
