import type { Context } from 'hono';
import { z } from 'zod';

import { executeInBatches, getDb, nowString } from '../db/client';
import { getEnvUsize } from '../env';
import { AppError } from '../errors';
import { readJson } from '../http/body';
import { jsonResponse } from '../http/rawJson';
import { buildCipherData, cipherRequestSchema, typeFieldsOf } from '../models/cipher';
import { publishUserUpdate } from '../notifications/publish';
import type { AppEnv } from '../types';

const importSchema = z.object({
  ciphers: z.array(z.unknown()),
  folders: z.array(z.object({ id: z.string().nullish(), name: z.string() })).nullish(),
  folderRelationships: z.array(z.object({ key: z.number(), value: z.number() })).nullish(),
});

const SYNC_VAULT = 5;

/** `POST /api/ciphers/import` */
export async function importDataHandler(c: Context<AppEnv>): Promise<Response> {
  const payload = await readJson(c.req.raw, importSchema);
  const db = getDb(c.env);
  const claims = c.get('claims');
  const now = nowString();
  const batchSize = getEnvUsize(c.env, 'IMPORT_BATCH_SIZE', 30);

  // ── folders ────────────────────────────────────────────────────────
  const existing = await db
    .prepare('SELECT id FROM folders WHERE user_id = ?1')
    .bind(claims.sub)
    .all<{ id: string }>();
  const existingIds = new Set((existing.results ?? []).map((row) => row.id));

  const folderIds: string[] = [];
  const folderStatements: D1PreparedStatement[] = [];

  for (const folder of payload.folders ?? []) {
    const id =
      folder.id !== undefined && folder.id !== null && folder.id.length > 0
        ? folder.id
        : crypto.randomUUID();
    folderIds.push(id);

    if (existingIds.has(id)) continue;
    folderStatements.push(
      db
        .prepare(
          'INSERT INTO folders (id, user_id, name, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?4)',
        )
        .bind(id, claims.sub, folder.name, now),
    );
  }

  // ── ciphers ────────────────────────────────────────────────────────
  const relations = new Map<number, number>();
  for (const relation of payload.folderRelationships ?? []) {
    relations.set(relation.key, relation.value);
  }

  const cipherStatements: D1PreparedStatement[] = [];

  for (const [index, raw] of payload.ciphers.entries()) {
    const parsed = cipherRequestSchema.safeParse(raw);
    if (!parsed.success) {
      throw AppError.jsonData(
        parsed.error.issues
          .map((issue) => `${issue.path.map(String).join('.')}: ${issue.message}`)
          .join(', '),
      );
    }
    const request = parsed.data;

    const folderIndex = relations.get(index);
    const folderId = folderIndex === undefined ? null : (folderIds[folderIndex] ?? null);
    const data = JSON.stringify(
      buildCipherData({
        name: request.name,
        notes: request.notes,
        typeFields: typeFieldsOf(request),
      }),
    );

    cipherStatements.push(
      db
        .prepare(
          `INSERT INTO ciphers (id, user_id, organization_id, type, data, favorite, folder_id, deleted_at, archived_at, created_at, updated_at)
           VALUES (?1, ?2, NULL, ?3, ?4, 0, ?5, NULL, NULL, ?6, ?6)`,
        )
        .bind(crypto.randomUUID(), claims.sub, request.type, data, folderId, now),
    );
  }

  try {
    await executeInBatches(db, folderStatements, batchSize);
    await executeInBatches(db, cipherStatements, batchSize);
  } catch (error) {
    throw AppError.database();
  }

  await db.prepare('UPDATE users SET updated_at = ?1 WHERE id = ?2').bind(now, claims.sub).run();

  publishUserUpdate(c.env, claims.sub, SYNC_VAULT, now, claims.device);

  return jsonResponse(null);
}
