import type { Context } from 'hono';
import { z } from 'zod';

import { assertMasterPassword } from '../auth/verify';
import { getDb, nowString } from '../db/client';
import { listAttachmentKeysForCiphers, listAttachmentKeysForUser } from '../db/storageKeys';
import { AppError } from '../errors';
import { readJson } from '../http/body';
import { jsonResponse } from '../http/rawJson';
import { buildCipherResponse, type CipherRow, cipherListResponse } from '../models/cipherResponse';
import type { UserRow } from '../models/user';
import { publishCipherUpdate, publishUserUpdate } from '../notifications/publish';
import { attachmentsEnabled, deleteStorageObjects } from '../storage';
import type { AppEnv } from '../types';

const SYNC_CIPHER_UPDATE = 0;
const SYNC_LOGIN_DELETE = 2;
const SYNC_CIPHERS = 4;
const SYNC_VAULT = 5;

const ARCHIVE_FAILED =
  'Cipher was not archived. Ensure the provided ID is correct and you have permission to archive it.';
const UNARCHIVE_FAILED =
  'Cipher was not unarchived. Ensure the provided ID is correct and you have permission to unarchive it.';
const FOLDER_INVALID = 'Invalid folder: Folder does not exist or belongs to another user';

function placeholders(count: number, startAt = 1): string {
  return Array.from({ length: count }, (_, index) => `?${startAt + index}`).join(', ');
}

/** Bulk endpoints take a raw `{"ids": [...]}` body; a null/missing body is a no-op. */
async function readIds(c: Context<AppEnv>): Promise<string[]> {
  const body = await readJson(c.req.raw, z.unknown());
  if (body === null || typeof body !== 'object' || Array.isArray(body)) {
    throw AppError.badRequest('Malformed JSON in request body');
  }

  const ids = (body as Record<string, unknown>).ids;
  if (ids === undefined || ids === null) return [];
  if (!Array.isArray(ids)) throw AppError.badRequest('Malformed JSON in request body');
  return ids.filter((value): value is string => typeof value === 'string');
}

async function touchUser(c: Context<AppEnv>, now: string): Promise<void> {
  await getDb(c.env)
    .prepare('UPDATE users SET updated_at = ?1 WHERE id = ?2')
    .bind(now, c.get('claims').sub)
    .run();
}

async function selectByIds(c: Context<AppEnv>, ids: string[]): Promise<CipherRow[]> {
  if (ids.length === 0) return [];
  const rows = await getDb(c.env)
    .prepare(`SELECT * FROM ciphers WHERE user_id = ?1 AND id IN (${placeholders(ids.length, 2)})`)
    .bind(c.get('claims').sub, ...ids)
    .all<CipherRow>();
  return rows.results ?? [];
}

/** `PUT /api/ciphers/delete` — bulk soft delete. */
export async function bulkSoftDeleteHandler(c: Context<AppEnv>): Promise<Response> {
  const ids = await readIds(c);
  const claims = c.get('claims');
  const now = nowString();

  if (ids.length > 0) {
    await getDb(c.env)
      .prepare(
        `UPDATE ciphers SET deleted_at = ?1, updated_at = ?1 WHERE user_id = ?2 AND id IN (${placeholders(ids.length, 3)})`,
      )
      .bind(now, claims.sub, ...ids)
      .run();
    await touchUser(c, now);
  }

  publishUserUpdate(c.env, claims.sub, SYNC_CIPHERS, now, claims.device);
  return jsonResponse(null);
}

/** `POST /api/ciphers/delete` and `DELETE /api/ciphers` — bulk hard delete. */
export async function bulkHardDeleteHandler(c: Context<AppEnv>): Promise<Response> {
  const ids = await readIds(c);
  const claims = c.get('claims');
  const now = nowString();

  if (ids.length > 0) {
    // Attachment objects first: the key query joins on `ciphers`.
    if (attachmentsEnabled(c.env)) {
      const keys = await listAttachmentKeysForCiphers(getDb(c.env), claims.sub, ids);
      await deleteStorageObjects(c.env, keys);
    }

    await getDb(c.env)
      .prepare(`DELETE FROM ciphers WHERE user_id = ?1 AND id IN (${placeholders(ids.length, 2)})`)
      .bind(claims.sub, ...ids)
      .run();
    await touchUser(c, now);
  }

  publishUserUpdate(c.env, claims.sub, SYNC_LOGIN_DELETE, now, claims.device);
  return jsonResponse(null);
}

/** `PUT /api/ciphers/restore` — returns the restored ciphers. */
export async function bulkRestoreHandler(c: Context<AppEnv>): Promise<Response> {
  const ids = await readIds(c);
  const claims = c.get('claims');
  const now = nowString();

  if (ids.length > 0) {
    await getDb(c.env)
      .prepare(
        `UPDATE ciphers SET deleted_at = NULL, updated_at = ?1 WHERE user_id = ?2 AND id IN (${placeholders(ids.length, 3)})`,
      )
      .bind(now, claims.sub, ...ids)
      .run();
    await touchUser(c, now);
  }

  publishUserUpdate(c.env, claims.sub, SYNC_CIPHERS, now, claims.device);
  return cipherListResponse((await selectByIds(c, ids)).map((row) => buildCipherResponse(row)));
}

async function setArchived(c: Context<AppEnv>, archived: boolean): Promise<Response> {
  const ids = await readIds(c);
  const claims = c.get('claims');
  const now = nowString();

  if (ids.length > 0) {
    await getDb(c.env)
      .prepare(
        `UPDATE ciphers SET archived_at = ?1, updated_at = ?2 WHERE user_id = ?3 AND id IN (${placeholders(ids.length, 4)})`,
      )
      .bind(archived ? now : null, now, claims.sub, ...ids)
      .run();
    await touchUser(c, now);
  }

  publishUserUpdate(c.env, claims.sub, SYNC_CIPHERS, now, claims.device);
  return cipherListResponse((await selectByIds(c, ids)).map((row) => buildCipherResponse(row)));
}

/** `PUT /api/ciphers/archive` */
export async function bulkArchiveHandler(c: Context<AppEnv>): Promise<Response> {
  return setArchived(c, true);
}

/** `PUT /api/ciphers/unarchive` */
export async function bulkUnarchiveHandler(c: Context<AppEnv>): Promise<Response> {
  return setArchived(c, false);
}

async function setArchivedSingle(c: Context<AppEnv>, archived: boolean): Promise<Response> {
  const claims = c.get('claims');
  const now = nowString();
  const id = c.req.param('id') ?? '';

  const row = await getDb(c.env)
    .prepare('SELECT * FROM ciphers WHERE id = ?1 AND user_id = ?2')
    .bind(id, claims.sub)
    .first<CipherRow>();

  if (row === null) {
    throw AppError.badRequest(archived ? ARCHIVE_FAILED : UNARCHIVE_FAILED);
  }

  await getDb(c.env)
    .prepare('UPDATE ciphers SET archived_at = ?1, updated_at = ?2 WHERE id = ?3 AND user_id = ?4')
    .bind(archived ? now : null, now, id, claims.sub)
    .run();

  publishCipherUpdate(c.env, claims.sub, SYNC_CIPHER_UPDATE, id, now, claims.device);

  return jsonResponse(
    buildCipherResponse({ ...row, archived_at: archived ? now : null, updated_at: now }),
  );
}

/** `PUT /api/ciphers/{id}/archive` */
export async function archiveCipherHandler(c: Context<AppEnv>): Promise<Response> {
  return setArchivedSingle(c, true);
}

/** `PUT /api/ciphers/{id}/unarchive` */
export async function unarchiveCipherHandler(c: Context<AppEnv>): Promise<Response> {
  return setArchivedSingle(c, false);
}

/** `POST|PUT /api/ciphers/move` */
export async function moveCipherHandler(c: Context<AppEnv>): Promise<Response> {
  const body = await readJson(
    c.req.raw,
    z.object({
      folderId: z.string().nullish(),
      ids: z.array(z.string()).nullish(),
    }),
  );

  const claims = c.get('claims');
  const now = nowString();
  const folderId =
    body.folderId === undefined || body.folderId === '' ? null : (body.folderId ?? null);
  const ids = body.ids ?? [];

  if (folderId !== null) {
    const folder = await getDb(c.env)
      .prepare('SELECT id FROM folders WHERE id = ?1 AND user_id = ?2')
      .bind(folderId, claims.sub)
      .first<{ id: string }>();
    if (folder === null) throw AppError.badRequest(FOLDER_INVALID);
  }

  if (ids.length > 0) {
    await getDb(c.env)
      .prepare(
        `UPDATE ciphers SET folder_id = ?1, updated_at = ?2 WHERE user_id = ?3 AND id IN (${placeholders(ids.length, 4)})`,
      )
      .bind(folderId, now, claims.sub, ...ids)
      .run();
    await touchUser(c, now);
  }

  publishUserUpdate(c.env, claims.sub, SYNC_CIPHERS, now, claims.device);
  return jsonResponse(null);
}

/** `POST /api/ciphers/purge` — wipe the vault after password verification. */
export async function purgeVaultHandler(c: Context<AppEnv>): Promise<Response> {
  const payload = await readJson(
    c.req.raw,
    z.object({
      masterPasswordHash: z.string().nullish(),
      MasterPasswordHash: z.string().nullish(),
    }),
  );

  const hash = payload.masterPasswordHash ?? payload.MasterPasswordHash;
  if (hash === undefined || hash === null) {
    throw AppError.badRequest('Missing master password hash');
  }

  const db = getDb(c.env);
  const claims = c.get('claims');
  const user = await db
    .prepare('SELECT * FROM users WHERE id = ?1')
    .bind(claims.sub)
    .first<UserRow>();
  if (user === null) throw AppError.notFound('User not found');

  assertMasterPassword(user, hash);

  const now = nowString();
  // Wipe the attachment objects before the rows they belong to disappear.
  if (attachmentsEnabled(c.env)) {
    const keys = await listAttachmentKeysForUser(db, claims.sub);
    await deleteStorageObjects(c.env, keys);
  }

  await db.prepare('DELETE FROM ciphers WHERE user_id = ?1').bind(claims.sub).run();
  await db.prepare('DELETE FROM folders WHERE user_id = ?1').bind(claims.sub).run();
  await touchUser(c, now);

  publishUserUpdate(c.env, claims.sub, SYNC_VAULT, now, claims.device);
  return jsonResponse(null);
}
