import type { Context } from 'hono';
import { z } from 'zod';

import { getDb, nowString } from '../db/client';
import { AppError } from '../errors';
import { readJson } from '../http/body';
import { jsonResponse } from '../http/rawJson';
import {
  buildCipherData,
  type CipherRequest,
  cipherRequestSchema,
  typeFieldsOf,
} from '../models/cipher';
import { buildCipherResponse, type CipherRow, cipherListResponse } from '../models/cipherResponse';
import { publishCipherUpdate } from '../notifications/publish';
import type { AppEnv } from '../types';

const CIPHER_NOT_FOUND = 'Cipher not found';
const FOLDER_INVALID = 'Invalid folder: Folder does not exist or belongs to another user';
const STALE_REVISION =
  'The client copy of this cipher is out of date. Resync the client and try again.';

/** UpdateType values used by cipher mutations. */
const SYNC_CIPHER_UPDATE = 0;
const SYNC_CIPHER_CREATE = 1;
const SYNC_LOGIN_DELETE = 2;
const SYNC_CIPHERS = 4;
const SYNC_VAULT = 5;

function parseCipherRequest(value: unknown): CipherRequest {
  const result = cipherRequestSchema.safeParse(value);
  if (!result.success) {
    const detail = result.error.issues
      .map((issue) => `${issue.path.map(String).join('.')}: ${issue.message}`)
      .join(', ');
    throw AppError.jsonData(detail);
  }
  return result.data;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

/** Accept both the flat body and the `{cipher: ...}` wrapper used by `/create`. */
function unwrapCipherBody(body: unknown): unknown {
  if (!isRecord(body)) return body;
  if ('cipher' in body) return body.cipher;
  if ('Cipher' in body) return body.Cipher;
  return body;
}

async function loadCipher(c: Context<AppEnv>, id: string): Promise<CipherRow> {
  const row = await getDb(c.env)
    .prepare('SELECT * FROM ciphers WHERE id = ?1 AND user_id = ?2')
    .bind(id, c.get('claims').sub)
    .first<CipherRow>();
  if (row === null) throw AppError.notFound(CIPHER_NOT_FOUND);
  return row;
}

async function validateFolder(c: Context<AppEnv>, folderId: string | null): Promise<void> {
  if (folderId === null) return;
  const folder = await getDb(c.env)
    .prepare('SELECT id FROM folders WHERE id = ?1 AND user_id = ?2')
    .bind(folderId, c.get('claims').sub)
    .first<{ id: string }>();
  if (folder === null) throw AppError.badRequest(FOLDER_INVALID);
}

/** `GET /api/ciphers` — excludes trashed ciphers, newest first. */
export async function listCiphersHandler(c: Context<AppEnv>): Promise<Response> {
  const rows = await getDb(c.env)
    .prepare(
      'SELECT * FROM ciphers WHERE user_id = ?1 AND deleted_at IS NULL ORDER BY updated_at DESC',
    )
    .bind(c.get('claims').sub)
    .all<CipherRow>();

  return cipherListResponse((rows.results ?? []).map((row) => buildCipherResponse(row)));
}

/** `GET /api/ciphers/{id}` and `/details` — trashed ciphers are still returned. */
export async function getCipherHandler(c: Context<AppEnv>): Promise<Response> {
  const row = await loadCipher(c, c.req.param('id') ?? '');
  return jsonResponse(buildCipherResponse(row));
}

/** `POST /api/ciphers` and `POST /api/ciphers/create`. */
export async function createCipherHandler(c: Context<AppEnv>): Promise<Response> {
  const body = await readJson(c.req.raw, z.unknown());
  const request = parseCipherRequest(unwrapCipherBody(body));

  const folderId = request.folderId ?? null;
  await validateFolder(c, folderId);

  const claims = c.get('claims');
  const now = nowString();
  const id = crypto.randomUUID();
  const data = JSON.stringify(
    buildCipherData({
      name: request.name,
      notes: request.notes,
      typeFields: typeFieldsOf(request),
    }),
  );
  const favorite = request.favorite ?? false;

  await getDb(c.env)
    .prepare(
      `INSERT INTO ciphers (id, user_id, organization_id, type, data, favorite, folder_id, deleted_at, archived_at, created_at, updated_at)
       VALUES (?1, ?2, NULL, ?3, ?4, ?5, ?6, NULL, NULL, ?7, ?7)`,
    )
    .bind(id, claims.sub, request.type, data, favorite ? 1 : 0, folderId, now)
    .run();

  await getDb(c.env)
    .prepare('UPDATE users SET updated_at = ?1 WHERE id = ?2')
    .bind(now, claims.sub)
    .run();

  publishCipherUpdate(c.env, claims.sub, SYNC_CIPHER_CREATE, id, now, claims.device);

  return jsonResponse(
    buildCipherResponse(
      {
        id,
        user_id: claims.sub,
        organization_id: null,
        type: request.type,
        data,
        favorite: favorite ? 1 : 0,
        folder_id: folderId,
        deleted_at: null,
        archived_at: null,
        created_at: now,
        updated_at: now,
      },
      null,
      'cipher',
    ),
  );
}

/** `PUT|POST /api/ciphers/{id}` */
export async function updateCipherHandler(c: Context<AppEnv>): Promise<Response> {
  const body = await readJson(c.req.raw, z.unknown());
  const request = parseCipherRequest(unwrapCipherBody(body));
  const row = await loadCipher(c, c.req.param('id') ?? '');

  if (request.lastKnownRevisionDate !== undefined && request.lastKnownRevisionDate !== null) {
    const client = Date.parse(request.lastKnownRevisionDate);
    const server = Date.parse(row.updated_at);
    if (!Number.isNaN(client) && !Number.isNaN(server) && server - client > 1000) {
      throw AppError.badRequest(STALE_REVISION);
    }
  }

  const folderId = request.folderId ?? null;
  await validateFolder(c, folderId);

  const claims = c.get('claims');
  const now = nowString();
  const data = JSON.stringify(
    buildCipherData({
      name: request.name,
      notes: request.notes,
      typeFields: typeFieldsOf(request),
    }),
  );
  const favorite = request.favorite ?? false;

  await getDb(c.env)
    .prepare(
      'UPDATE ciphers SET type = ?1, data = ?2, folder_id = ?3, favorite = ?4, updated_at = ?5 WHERE id = ?6 AND user_id = ?7',
    )
    .bind(request.type, data, folderId, favorite ? 1 : 0, now, row.id, claims.sub)
    .run();

  await getDb(c.env)
    .prepare('UPDATE users SET updated_at = ?1 WHERE id = ?2')
    .bind(now, claims.sub)
    .run();

  publishCipherUpdate(c.env, claims.sub, SYNC_CIPHER_UPDATE, row.id, now, claims.device);

  return jsonResponse(
    buildCipherResponse(
      {
        ...row,
        type: request.type,
        data,
        folder_id: folderId,
        favorite: favorite ? 1 : 0,
        updated_at: now,
      },
      null,
      'cipher',
    ),
  );
}

/** `PUT /api/ciphers/{id}/partial` — folder / favorite only. */
export async function partialCipherHandler(c: Context<AppEnv>): Promise<Response> {
  const schema = z.object({ folderId: z.string().nullish(), favorite: z.boolean().optional() });
  const payload = await readJson(c.req.raw, schema);
  const row = await loadCipher(c, c.req.param('id') ?? '');

  // Rust treats an absent folderId as "move to no folder".
  const folderId = payload.folderId ?? null;
  if (payload.folderId !== undefined) {
    await validateFolder(c, folderId);
  }

  const favorite = payload.favorite === undefined ? row.favorite : payload.favorite ? 1 : 0;
  const claims = c.get('claims');
  const now = nowString();

  await getDb(c.env)
    .prepare(
      'UPDATE ciphers SET folder_id = ?1, favorite = ?2, updated_at = ?3 WHERE id = ?4 AND user_id = ?5',
    )
    .bind(folderId, favorite, now, row.id, claims.sub)
    .run();

  publishCipherUpdate(c.env, claims.sub, SYNC_CIPHER_UPDATE, row.id, now, claims.device);

  return jsonResponse(
    buildCipherResponse({ ...row, folder_id: folderId, favorite, updated_at: now }),
  );
}

/** `PUT /api/ciphers/{id}/delete` — soft delete. */
export async function softDeleteCipherHandler(c: Context<AppEnv>): Promise<Response> {
  const row = await loadCipher(c, c.req.param('id') ?? '');
  const claims = c.get('claims');
  const now = nowString();

  await getDb(c.env)
    .prepare('UPDATE ciphers SET deleted_at = ?1, updated_at = ?1 WHERE id = ?2 AND user_id = ?3')
    .bind(now, row.id, claims.sub)
    .run();
  await getDb(c.env)
    .prepare('UPDATE users SET updated_at = ?1 WHERE id = ?2')
    .bind(now, claims.sub)
    .run();

  publishCipherUpdate(c.env, claims.sub, SYNC_CIPHER_UPDATE, row.id, now, claims.device);

  return jsonResponse(null);
}

/** `PUT /api/ciphers/{id}/restore` */
export async function restoreCipherHandler(c: Context<AppEnv>): Promise<Response> {
  const row = await loadCipher(c, c.req.param('id') ?? '');
  const claims = c.get('claims');
  const now = nowString();

  await getDb(c.env)
    .prepare('UPDATE ciphers SET deleted_at = NULL, updated_at = ?1 WHERE id = ?2 AND user_id = ?3')
    .bind(now, row.id, claims.sub)
    .run();

  publishCipherUpdate(c.env, claims.sub, SYNC_CIPHER_UPDATE, row.id, now, claims.device);

  return jsonResponse(buildCipherResponse({ ...row, deleted_at: null, updated_at: now }));
}

/** `DELETE /api/ciphers/{id}` and `POST /api/ciphers/{id}/delete` — hard delete. */
export async function hardDeleteCipherHandler(c: Context<AppEnv>): Promise<Response> {
  const row = await loadCipher(c, c.req.param('id') ?? '');
  const claims = c.get('claims');
  const now = nowString();

  await getDb(c.env)
    .prepare('DELETE FROM ciphers WHERE id = ?1 AND user_id = ?2')
    .bind(row.id, claims.sub)
    .run();
  await getDb(c.env)
    .prepare('UPDATE users SET updated_at = ?1 WHERE id = ?2')
    .bind(now, claims.sub)
    .run();

  publishCipherUpdate(c.env, claims.sub, SYNC_LOGIN_DELETE, row.id, now, claims.device);

  return jsonResponse(null);
}

/** Exported for the bulk handlers (next iteration). */
export const cipherNotificationTypes = {
  SYNC_CIPHER_UPDATE,
  SYNC_CIPHER_CREATE,
  SYNC_LOGIN_DELETE,
  SYNC_CIPHERS,
  SYNC_VAULT,
};
