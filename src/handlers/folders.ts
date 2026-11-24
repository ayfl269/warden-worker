import type { Context } from 'hono';
import { z } from 'zod';

import { getDb, nowString } from '../db/client';
import { AppError } from '../errors';
import { readJson } from '../http/body';
import { jsonResponse } from '../http/rawJson';
import { publishFolderUpdate } from '../notifications/publish';
import type { AppEnv } from '../types';

const FOLDER_INVALID = 'Invalid folder: Folder does not exist or belongs to another user';

/** `SyncFolderCreate = 7`, `SyncFolderUpdate = 8`, `SyncFolderDelete = 3`. */
const SYNC_FOLDER_DELETE = 3;
const SYNC_FOLDER_CREATE = 7;
const SYNC_FOLDER_UPDATE = 8;

const folderSchema = z.object({ name: z.string() });

interface FolderRow {
  id: string;
  user_id: string;
  name: string;
  created_at: string;
  updated_at: string;
}

function toJson(row: FolderRow): Record<string, unknown> {
  return { id: row.id, name: row.name, revisionDate: row.updated_at, object: 'folder' };
}

/** `GET /api/folders` — no ORDER BY, matching the Rust query. */
export async function listFoldersHandler(c: Context<AppEnv>): Promise<Response> {
  const rows = await getDb(c.env)
    .prepare('SELECT * FROM folders WHERE user_id = ?1')
    .bind(c.get('claims').sub)
    .all<FolderRow>();

  return jsonResponse({
    data: (rows.results ?? []).map(toJson),
    object: 'list',
    continuationToken: null,
  });
}

/** `POST /api/folders` */
export async function createFolderHandler(c: Context<AppEnv>): Promise<Response> {
  const payload = await readJson(c.req.raw, folderSchema);
  const claims = c.get('claims');
  const now = nowString();
  const id = crypto.randomUUID();

  await getDb(c.env)
    .prepare(
      'INSERT INTO folders (id, user_id, name, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?4)',
    )
    .bind(id, claims.sub, payload.name, now)
    .run();

  publishFolderUpdate(c.env, claims.sub, SYNC_FOLDER_CREATE, id, now, claims.device);

  return jsonResponse({ id, name: payload.name, revisionDate: now, object: 'folder' });
}

/** `GET /api/folders/{id}` — 400 (not 404) when the folder is missing. */
export async function getFolderHandler(c: Context<AppEnv>): Promise<Response> {
  const row = await getDb(c.env)
    .prepare('SELECT * FROM folders WHERE id = ?1 AND user_id = ?2')
    .bind(c.req.param('id') ?? '', c.get('claims').sub)
    .first<FolderRow>();

  if (row === null) throw AppError.badRequest(FOLDER_INVALID);
  return jsonResponse(toJson(row));
}

/** `PUT /api/folders/{id}` — 404 when the folder is missing. */
export async function updateFolderHandler(c: Context<AppEnv>): Promise<Response> {
  const payload = await readJson(c.req.raw, folderSchema);
  const row = await getDb(c.env)
    .prepare('SELECT * FROM folders WHERE id = ?1 AND user_id = ?2')
    .bind(c.req.param('id') ?? '', c.get('claims').sub)
    .first<FolderRow>();

  if (row === null) throw AppError.notFound('Folder not found');

  const claims = c.get('claims');
  const now = nowString();
  await getDb(c.env)
    .prepare('UPDATE folders SET name = ?1, updated_at = ?2 WHERE id = ?3 AND user_id = ?4')
    .bind(payload.name, now, row.id, claims.sub)
    .run();

  publishFolderUpdate(c.env, claims.sub, SYNC_FOLDER_UPDATE, row.id, now, claims.device);

  return jsonResponse({ id: row.id, name: payload.name, revisionDate: now, object: 'folder' });
}

/** `DELETE /api/folders/{id}` and `POST /api/folders/{id}/delete` — no existence check. */
export async function deleteFolderHandler(c: Context<AppEnv>): Promise<Response> {
  const claims = c.get('claims');
  const now = nowString();

  await getDb(c.env)
    .prepare('DELETE FROM folders WHERE id = ?1 AND user_id = ?2')
    .bind(c.req.param('id') ?? '', claims.sub)
    .run();

  publishFolderUpdate(
    c.env,
    claims.sub,
    SYNC_FOLDER_DELETE,
    c.req.param('id') ?? '',
    now,
    claims.device,
  );

  return jsonResponse(null);
}
