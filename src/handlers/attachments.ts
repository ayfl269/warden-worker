import type { Context } from 'hono';
import { z } from 'zod';

import { attachmentTtl, signAttachmentToken } from '../auth/fileTokens';
import { getDb, nowString } from '../db/client';
import { AppError } from '../errors';
import { readJson } from '../http/body';
import { jsonResponse } from '../http/rawJson';
import { buildCipherResponse, type CipherRow } from '../models/cipherResponse';
import { publishCipherUpdate } from '../notifications/publish';
import {
  attachmentStorageKey,
  attachmentsEnabled,
  deleteStorageObject,
  displaySize,
  putStorageBytes,
} from '../storage';
import type { AppEnv } from '../types';

const SYNC_CIPHER_UPDATE = 0;
const NOT_ENABLED = 'Attachments are not enabled';
const CIPHER_NOT_FOUND = 'Cipher not found';
const ATTACHMENT_NOT_FOUND = 'Attachment not found';

interface AttachmentRow {
  id: string;
  cipher_id: string;
  file_name: string;
  file_size: number;
  akey: string | null;
  created_at: string;
  updated_at: string;
  organization_id: string | null;
}

const numberOrString = z.union([z.number(), z.string()]);

const createV2Schema = z.object({
  key: z.string(),
  fileName: z.string(),
  fileSize: numberOrString,
  adminRequest: z.boolean().optional(),
});

function parseSize(value: number | string): number {
  const parsed = typeof value === 'number' ? value : Number.parseInt(value, 10);
  return Number.isFinite(parsed) ? parsed : 0;
}

async function loadCipher(c: Context<AppEnv>, id: string): Promise<CipherRow> {
  const row = await getDb(c.env)
    .prepare('SELECT * FROM ciphers WHERE id = ?1 AND user_id = ?2')
    .bind(id, c.get('claims').sub)
    .first<CipherRow>();
  if (row === null) throw AppError.notFound(CIPHER_NOT_FOUND);
  if (row.organization_id !== null) {
    throw AppError.badRequest('Organization attachments are not supported');
  }
  if (row.deleted_at !== null) {
    throw AppError.badRequest('Cipher is deleted');
  }
  return row;
}

async function userAttachmentUsage(c: Context<AppEnv>, userId: string): Promise<number> {
  const db = getDb(c.env);
  const committed = await db
    .prepare(
      'SELECT COALESCE(SUM(a.file_size), 0) AS total FROM attachments a JOIN ciphers c ON c.id = a.cipher_id WHERE c.user_id = ?1',
    )
    .bind(userId)
    .first<{ total: number }>();
  const pending = await db
    .prepare(
      'SELECT COALESCE(SUM(p.file_size), 0) AS total FROM attachments_pending p JOIN ciphers c ON c.id = p.cipher_id WHERE c.user_id = ?1',
    )
    .bind(userId)
    .first<{ total: number }>();
  return (committed?.total ?? 0) + (pending?.total ?? 0);
}

async function enforceLimits(c: Context<AppEnv>, size: number): Promise<void> {
  const maxBytes = c.env.ATTACHMENT_MAX_BYTES;
  if (maxBytes !== undefined) {
    const limit = Number.parseInt(maxBytes, 10);
    if (Number.isSafeInteger(limit) && size > limit) {
      throw AppError.badRequest(`Attachment exceeds the maximum size of ${limit} bytes`);
    }
  }

  const totalKb = c.env.ATTACHMENT_TOTAL_LIMIT_KB;
  if (totalKb !== undefined) {
    const limit = Number.parseInt(totalKb, 10);
    if (Number.isSafeInteger(limit)) {
      const usage = await userAttachmentUsage(c, c.get('claims').sub);
      if (usage + size > limit * 1024) {
        throw AppError.badRequest('Attachment storage limit reached');
      }
    }
  }
}

function pendingToJson(row: AttachmentRow): Record<string, unknown> {
  return {
    id: row.id,
    url: null,
    fileName: row.file_name,
    size: String(row.file_size),
    sizeName: displaySize(row.file_size),
    key: row.akey,
    object: 'attachment',
  };
}

/** `POST /api/ciphers/{id}/attachment/v2` */
export async function createAttachmentV2Handler(c: Context<AppEnv>): Promise<Response> {
  if (!attachmentsEnabled(c.env)) throw AppError.badRequest(NOT_ENABLED);

  const payload = await readJson(c.req.raw, createV2Schema);
  const cipher = await loadCipher(c, c.req.param('id') ?? '');

  const declaredSize = parseSize(payload.fileSize);
  if (declaredSize <= 0) {
    throw AppError.badRequest('Attachment size must be positive');
  }
  await enforceLimits(c, declaredSize);

  const claims = c.get('claims');
  const now = nowString();
  const attachmentId = crypto.randomUUID();
  const db = getDb(c.env);

  await db
    .prepare(
      `INSERT INTO attachments_pending (id, cipher_id, file_name, file_size, akey, created_at, updated_at, organization_id)
       VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6, NULL)`,
    )
    .bind(attachmentId, cipher.id, payload.fileName, declaredSize, payload.key, now)
    .run();

  const token = await signAttachmentToken(
    c.env,
    {
      sub: claims.sub,
      device: claims.device,
      cipher_id: cipher.id,
      attachment_id: attachmentId,
    },
    attachmentTtl(c.env),
  );

  const pending: AttachmentRow = {
    id: attachmentId,
    cipher_id: cipher.id,
    file_name: payload.fileName,
    file_size: declaredSize,
    akey: payload.key,
    created_at: now,
    updated_at: now,
    organization_id: null,
  };

  const cipherResponse = buildCipherResponse(cipher, [pendingToJson(pending) as never]);

  return jsonResponse({
    object: 'attachment-fileUpload',
    attachmentId,
    url: `${c.get('baseUrl')}/api/ciphers/${cipher.id}/attachment/${attachmentId}/azure-upload?token=${token}`,
    fileUploadType: 1,
    cipherResponse,
  });
}

/** `GET /api/ciphers/{id}/attachment/{attachmentId}` */
export async function getAttachmentHandler(c: Context<AppEnv>): Promise<Response> {
  const cipher = await loadCipher(c, c.req.param('id') ?? '');
  const attachmentId = c.req.param('attachmentId') ?? '';

  const row = await getDb(c.env)
    .prepare('SELECT * FROM attachments WHERE id = ?1 AND cipher_id = ?2')
    .bind(attachmentId, cipher.id)
    .first<AttachmentRow>();
  if (row === null) throw AppError.notFound(ATTACHMENT_NOT_FOUND);

  const token = await signAttachmentToken(
    c.env,
    {
      sub: c.get('claims').sub,
      device: c.get('claims').device,
      cipher_id: cipher.id,
      attachment_id: row.id,
    },
    attachmentTtl(c.env),
  );

  return jsonResponse({
    id: row.id,
    url: `${c.get('baseUrl')}/api/ciphers/${cipher.id}/attachment/${row.id}/download?token=${token}`,
    fileName: row.file_name,
    size: String(row.file_size),
    sizeName: displaySize(row.file_size),
    key: row.akey,
    object: 'attachment',
  });
}

/** `DELETE /api/ciphers/{id}/attachment/{attachmentId}` (+ `POST .../delete`) */
export async function deleteAttachmentHandler(c: Context<AppEnv>): Promise<Response> {
  const cipher = await loadCipher(c, c.req.param('id') ?? '');
  const attachmentId = c.req.param('attachmentId') ?? '';
  const db = getDb(c.env);

  const row = await db
    .prepare('SELECT * FROM attachments WHERE id = ?1 AND cipher_id = ?2')
    .bind(attachmentId, cipher.id)
    .first<AttachmentRow>();
  if (row === null) throw AppError.notFound(ATTACHMENT_NOT_FOUND);

  await deleteStorageObject(c.env, attachmentStorageKey(cipher.id, row.id));
  await db
    .prepare('DELETE FROM attachments WHERE id = ?1 AND cipher_id = ?2')
    .bind(row.id, cipher.id)
    .run();

  const claims = c.get('claims');
  const now = nowString();
  await db
    .prepare('UPDATE ciphers SET updated_at = ?1 WHERE id = ?2 AND user_id = ?3')
    .bind(now, cipher.id, claims.sub)
    .run();
  await db.prepare('UPDATE users SET updated_at = ?1 WHERE id = ?2').bind(now, claims.sub).run();

  publishCipherUpdate(c.env, claims.sub, SYNC_CIPHER_UPDATE, cipher.id, now, claims.device);

  return jsonResponse({
    cipher: buildCipherResponse({ ...cipher, updated_at: now }),
  });
}

async function readMultipartFile(request: Request): Promise<{ file: File; key: string | null }> {
  let form: FormData;
  try {
    form = await request.formData();
  } catch {
    throw AppError.badRequest('Invalid multipart data');
  }

  const entry = form.get('data');
  if (!(entry instanceof File)) {
    throw AppError.badRequest('No attachment data provided');
  }

  const keyEntry = form.get('key');
  return { file: entry, key: typeof keyEntry === 'string' ? keyEntry : null };
}

function attachmentJson(row: AttachmentRow): Record<string, unknown> {
  return {
    id: row.id,
    url: null,
    fileName: row.file_name,
    size: String(row.file_size),
    sizeName: displaySize(row.file_size),
    key: row.akey,
    object: 'attachment',
  };
}

/** `POST /api/ciphers/{id}/attachment` — legacy multipart upload. */
export async function uploadAttachmentLegacyHandler(c: Context<AppEnv>): Promise<Response> {
  if (!attachmentsEnabled(c.env)) throw AppError.badRequest(NOT_ENABLED);

  const cipher = await loadCipher(c, c.req.param('id') ?? '');
  const { file, key } = await readMultipartFile(c.req.raw);

  if (key === null || key.length === 0) {
    throw AppError.badRequest('No attachment key provided');
  }
  if (file.size <= 0) {
    throw AppError.badRequest('Attachment size must be positive');
  }
  if (file.name.length === 0) {
    throw AppError.badRequest('No filename provided');
  }
  await enforceLimits(c, file.size);

  const claims = c.get('claims');
  const now = nowString();
  const attachmentId = crypto.randomUUID();
  const bytes = new Uint8Array(await file.arrayBuffer());

  try {
    await putStorageBytes(c.env, attachmentStorageKey(cipher.id, attachmentId), bytes, file.size);
  } catch (error) {
    throw AppError.worker(error);
  }

  const db = getDb(c.env);
  await db
    .prepare(
      `INSERT INTO attachments (id, cipher_id, file_name, file_size, akey, created_at, updated_at, organization_id)
       VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6, NULL)`,
    )
    .bind(attachmentId, cipher.id, file.name, file.size, key, now)
    .run();
  await db
    .prepare('UPDATE ciphers SET updated_at = ?1 WHERE id = ?2 AND user_id = ?3')
    .bind(now, cipher.id, claims.sub)
    .run();
  await db.prepare('UPDATE users SET updated_at = ?1 WHERE id = ?2').bind(now, claims.sub).run();

  publishCipherUpdate(c.env, claims.sub, SYNC_CIPHER_UPDATE, cipher.id, now, claims.device);

  const row: AttachmentRow = {
    id: attachmentId,
    cipher_id: cipher.id,
    file_name: file.name,
    file_size: file.size,
    akey: key,
    created_at: now,
    updated_at: now,
    organization_id: null,
  };

  return jsonResponse(
    buildCipherResponse({ ...cipher, updated_at: now }, [attachmentJson(row) as never]),
  );
}

/** `POST /api/ciphers/{id}/attachment/{attachmentId}` — v2 multipart data upload. */
export async function uploadAttachmentV2DataHandler(c: Context<AppEnv>): Promise<Response> {
  if (!attachmentsEnabled(c.env)) throw AppError.badRequest(NOT_ENABLED);

  const cipher = await loadCipher(c, c.req.param('id') ?? '');
  const attachmentId = c.req.param('attachmentId') ?? '';
  const db = getDb(c.env);

  const pending = await db
    .prepare('SELECT * FROM attachments_pending WHERE id = ?1')
    .bind(attachmentId)
    .first<AttachmentRow>();
  if (pending === null) throw AppError.notFound(ATTACHMENT_NOT_FOUND);
  if (pending.cipher_id !== cipher.id) {
    throw AppError.badRequest('Attachment does not belong to cipher');
  }

  const { file, key } = await readMultipartFile(c.req.raw);
  if (file.size !== pending.file_size) {
    await db.prepare('DELETE FROM attachments_pending WHERE id = ?1').bind(attachmentId).run();
    throw AppError.badRequest(
      `Uploaded size (${file.size}) does not match declared size (${pending.file_size})`,
    );
  }

  const akey = pending.akey ?? key;
  if (akey === null || akey.length === 0) {
    throw AppError.badRequest('No attachment key provided');
  }

  const claims = c.get('claims');
  const now = nowString();
  const bytes = new Uint8Array(await file.arrayBuffer());

  try {
    await putStorageBytes(c.env, attachmentStorageKey(cipher.id, attachmentId), bytes, file.size);
  } catch (error) {
    throw AppError.worker(error);
  }

  await db.batch([
    db
      .prepare(
        `INSERT INTO attachments (id, cipher_id, file_name, file_size, akey, created_at, updated_at, organization_id)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6, ?7)`,
      )
      .bind(
        pending.id,
        pending.cipher_id,
        pending.file_name,
        pending.file_size,
        akey,
        now,
        pending.organization_id,
      ),
    db.prepare('DELETE FROM attachments_pending WHERE id = ?1').bind(pending.id),
    db.prepare('UPDATE ciphers SET updated_at = ?1 WHERE id = ?2').bind(now, cipher.id),
    db.prepare('UPDATE users SET updated_at = ?1 WHERE id = ?2').bind(now, claims.sub),
  ]);

  publishCipherUpdate(c.env, claims.sub, SYNC_CIPHER_UPDATE, cipher.id, now, claims.device);

  return jsonResponse(null);
}
