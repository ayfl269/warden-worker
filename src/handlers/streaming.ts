import {
  verifyAttachmentToken,
  verifySendDownloadToken,
  verifySendFileToken,
} from '../auth/fileTokens';
import { getDb, nowString } from '../db/client';
import type { Env } from '../env';
import { AppError } from '../errors';
import { SEND_COLUMNS, SEND_TYPE_FILE, type SendRow, validateSendAccess } from '../models/send';
import { publishCipherUpdate, publishSendUpdate } from '../notifications/publish';
import { attachmentStorageKey, getStorageBackend, sendStorageKey } from '../storage';

const SYNC_CIPHER_UPDATE = 0;

const DOWNLOAD_HEADERS = {
  'content-type': 'application/octet-stream',
  'content-disposition': 'attachment',
  'x-content-type-options': 'nosniff',
};

interface PendingRow {
  id: string;
  cipher_id: string;
  file_name: string;
  file_size: number;
  akey: string | null;
  created_at: string;
  updated_at: string;
  organization_id: string | null;
}

function segmentsOf(pathname: string): string[] {
  const trimmed = pathname.replace(/^\/+/, '').replace(/\/+$/, '');
  return trimmed.length === 0 ? [] : trimmed.split('/');
}

/**
 * Whether the request must be handled by the streaming layer.
 *
 * - PUT  /api/ciphers/{id}/attachment/{aid}/azure-upload
 * - PUT  /api/sends/{id}/file/{fid}/azure-upload
 * - GET  /api/ciphers/{id}/attachment/{aid}/download
 * - GET  /api/sends/{id}/{fid}   (except the `access`/`file` prefixes)
 */
export function isStreamingRoute(method: string, pathname: string): boolean {
  const segments = segmentsOf(pathname);
  const upper = method.toUpperCase();

  if (upper === 'PUT') {
    if (
      segments.length === 6 &&
      segments[0] === 'api' &&
      segments[1] === 'ciphers' &&
      segments[3] === 'attachment' &&
      segments[5] === 'azure-upload'
    ) {
      return true;
    }
    return (
      segments.length === 6 &&
      segments[0] === 'api' &&
      segments[1] === 'sends' &&
      segments[3] === 'file' &&
      segments[5] === 'azure-upload'
    );
  }

  if (upper === 'GET') {
    if (
      segments.length === 6 &&
      segments[0] === 'api' &&
      segments[1] === 'ciphers' &&
      segments[3] === 'attachment' &&
      segments[5] === 'download'
    ) {
      return true;
    }
    const [api, sends, sendId] = segments;
    return (
      segments.length === 4 &&
      api === 'api' &&
      sends === 'sends' &&
      sendId !== 'access' &&
      sendId !== 'file'
    );
  }

  return false;
}

function errorResponse(status: number, message: string): Response {
  return new Response(JSON.stringify({ error: message }), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

function toAppErrorResponse(error: unknown): Response {
  if (error instanceof AppError) {
    return error.toResponse();
  }
  console.error('[streaming] unhandled error', error);
  return errorResponse(500, 'Internal server error');
}

function requiredToken(url: URL, name = 'token'): string {
  const token = url.searchParams.get(name);
  if (token === null || token.length === 0) {
    throw AppError.badRequest(`Missing query parameter: ${name}`);
  }
  return token;
}

async function handleAttachmentUpload(
  request: Request,
  env: Env,
  url: URL,
  cipherId: string,
  attachmentId: string,
): Promise<Response> {
  const token = requiredToken(url);
  const claims = await verifyAttachmentToken(env, token);
  if (claims === null) throw AppError.unauthorized('Invalid token');
  if (claims.cipher_id !== cipherId || claims.attachment_id !== attachmentId) {
    throw AppError.unauthorized('Invalid token');
  }

  const backend = getStorageBackend(env);
  if (backend === null) throw AppError.badRequest('Attachments are not enabled');

  const db = getDb(env);
  const pending = await db
    .prepare('SELECT * FROM attachments_pending WHERE id = ?1 AND cipher_id = ?2')
    .bind(attachmentId, cipherId)
    .first<PendingRow>();
  if (pending === null) throw AppError.notFound('Attachment not found');

  const cipher = await db
    .prepare('SELECT id, user_id FROM ciphers WHERE id = ?1 AND user_id = ?2')
    .bind(cipherId, claims.sub)
    .first<{ id: string; user_id: string }>();
  if (cipher === null) throw AppError.notFound('Cipher not found');

  const contentLength = request.headers.get('content-length');
  if (contentLength === null) throw AppError.badRequest('Missing Content-Length header');
  const declared = Number.parseInt(contentLength, 10);
  if (!Number.isSafeInteger(declared) || declared < 0) {
    throw AppError.badRequest('Invalid Content-Length header');
  }
  if (declared !== pending.file_size) {
    throw AppError.badRequest(
      `Uploaded size (${declared}) does not match declared size (${pending.file_size})`,
    );
  }

  if (request.body === null) throw AppError.badRequest('Missing request body');
  const key = attachmentStorageKey(cipherId, attachmentId);

  if (backend.kind === 'r2') {
    const object = await backend.bucket.put(key, request.body);
    if (object === null) {
      throw AppError.worker(new Error('R2 put returned no object'));
    }
    if (object.size !== pending.file_size) {
      await backend.bucket.delete(key);
      throw AppError.badRequest(
        `Uploaded size (${object.size}) does not match declared size (${pending.file_size})`,
      );
    }
  } else {
    await backend.kv.put(key, request.body, {
      metadata: { file_size: pending.file_size },
    });
  }

  const now = nowString();
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
        pending.akey,
        now,
        pending.organization_id,
      ),
    db.prepare('DELETE FROM attachments_pending WHERE id = ?1').bind(pending.id),
    db.prepare('UPDATE ciphers SET updated_at = ?1 WHERE id = ?2').bind(now, cipherId),
    db.prepare('UPDATE users SET updated_at = ?1 WHERE id = ?2').bind(now, claims.sub),
  ]);

  publishCipherUpdate(env, claims.sub, SYNC_CIPHER_UPDATE, cipherId, now, claims.device);

  return new Response(null, { status: 201 });
}

async function handleAttachmentDownload(
  env: Env,
  url: URL,
  cipherId: string,
  attachmentId: string,
): Promise<Response> {
  const token = requiredToken(url);
  const claims = await verifyAttachmentToken(env, token);
  if (claims === null) throw AppError.unauthorized('Invalid token');
  if (claims.cipher_id !== cipherId || claims.attachment_id !== attachmentId) {
    throw AppError.unauthorized('Invalid token');
  }

  const backend = getStorageBackend(env);
  if (backend === null) throw AppError.badRequest('Attachments are not enabled');
  const key = attachmentStorageKey(cipherId, attachmentId);

  if (backend.kind === 'r2') {
    const object = await backend.bucket.get(key);
    if (object === null) throw AppError.notFound('Attachment not found');
    return new Response(object.body, {
      headers: { ...DOWNLOAD_HEADERS, 'content-length': String(object.size) },
    });
  }

  const result = (await backend.kv.getWithMetadata(key, 'stream')) as unknown as {
    value: ReadableStream | null;
    metadata: { file_size?: number } | null;
  };
  if (result.value === null) throw AppError.notFound('Attachment not found');

  const headers: Record<string, string> = { ...DOWNLOAD_HEADERS };
  if (result.metadata?.file_size !== undefined) {
    headers['content-length'] = String(result.metadata.file_size);
  }
  return new Response(result.value, { headers });
}

async function handleSendUpload(
  request: Request,
  env: Env,
  url: URL,
  sendId: string,
  fileId: string,
): Promise<Response> {
  const token = requiredToken(url);
  const claims = await verifySendFileToken(env, token);
  if (claims === null) throw AppError.unauthorized('Invalid token');
  if (claims.send_id !== sendId || claims.file_id !== fileId) {
    throw AppError.unauthorized('Invalid token');
  }

  const backend = getStorageBackend(env);
  if (backend === null) throw AppError.badRequest('File storage is not enabled');

  const db = getDb(env);
  const pending = await db
    .prepare(`SELECT ${SEND_COLUMNS} FROM sends_pending WHERE id = ?1 AND user_id = ?2`)
    .bind(sendId, claims.sub)
    .first<SendRow>();
  if (pending === null) throw AppError.notFound('Send not found');

  let declaredSize = 0;
  try {
    const parsed = JSON.parse(pending.data) as { size?: unknown };
    declaredSize =
      typeof parsed.size === 'number'
        ? parsed.size
        : typeof parsed.size === 'string'
          ? Number.parseInt(parsed.size, 10)
          : 0;
  } catch {
    declaredSize = 0;
  }

  const contentLength = request.headers.get('content-length');
  if (contentLength === null) throw AppError.badRequest('Missing Content-Length header');
  const declared = Number.parseInt(contentLength, 10);
  if (!Number.isSafeInteger(declared) || declared < 0) {
    throw AppError.badRequest('Invalid Content-Length header');
  }
  if (declared !== declaredSize) {
    throw AppError.badRequest(
      `Uploaded size (${declared}) does not match declared size (${declaredSize})`,
    );
  }
  if (request.body === null) throw AppError.badRequest('Missing request body');

  const key = sendStorageKey(sendId, fileId);
  if (backend.kind === 'r2') {
    const object = await backend.bucket.put(key, request.body);
    if (object === null) throw AppError.worker(new Error('R2 put returned no object'));
    if (object.size !== declaredSize) {
      await backend.bucket.delete(key);
      throw AppError.badRequest(
        `Uploaded size (${object.size}) does not match declared size (${declaredSize})`,
      );
    }
  } else {
    await backend.kv.put(key, request.body, { metadata: { file_size: declaredSize } });
  }

  const now = nowString();
  await db.batch([
    db
      .prepare(
        `INSERT INTO sends (${SEND_COLUMNS}) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, 0, ?12, ?12, ?13, ?14, ?15, ?16)`,
      )
      .bind(
        pending.id,
        pending.user_id,
        pending.name,
        pending.notes,
        pending.type,
        pending.data,
        pending.akey,
        pending.password_hash,
        pending.password_salt,
        pending.password_iter,
        pending.max_access_count,
        now,
        pending.expiration_date,
        pending.deletion_date,
        pending.disabled,
        pending.hide_email,
      ),
    db.prepare('DELETE FROM sends_pending WHERE id = ?1').bind(pending.id),
    db.prepare('UPDATE users SET updated_at = ?1 WHERE id = ?2').bind(now, claims.sub),
  ]);

  publishSendUpdate(env, claims.sub, 12, sendId, now, claims.device);

  return new Response(null, { status: 201 });
}

async function handleSendDownload(
  env: Env,
  url: URL,
  sendId: string,
  fileId: string,
): Promise<Response> {
  const token = url.searchParams.get('t') ?? '';
  const claims = await verifySendDownloadToken(env, token);
  if (claims === null || claims.send_id !== sendId || claims.file_id !== fileId) {
    throw AppError.notFound('Send does not exist or is no longer available');
  }

  const backend = getStorageBackend(env);
  if (backend === null) throw AppError.badRequest('File storage is not enabled');

  const db = getDb(env);
  const send = await db
    .prepare(`SELECT ${SEND_COLUMNS} FROM sends WHERE id = ?1`)
    .bind(sendId)
    .first<SendRow>();
  if (send === null || send.type !== SEND_TYPE_FILE) {
    throw AppError.notFound('Send does not exist or is no longer available');
  }
  validateSendAccess(send, nowString());

  const key = sendStorageKey(sendId, fileId);
  if (backend.kind === 'r2') {
    const object = await backend.bucket.get(key);
    if (object === null) throw AppError.notFound('Send does not exist or is no longer available');
    return new Response(object.body, {
      headers: { ...DOWNLOAD_HEADERS, 'content-length': String(object.size) },
    });
  }

  const result = (await backend.kv.getWithMetadata(key, 'stream')) as unknown as {
    value: ReadableStream | null;
    metadata: { file_size?: number } | null;
  };
  if (result.value === null) {
    throw AppError.notFound('Send does not exist or is no longer available');
  }
  const headers: Record<string, string> = { ...DOWNLOAD_HEADERS };
  if (result.metadata?.file_size !== undefined) {
    headers['content-length'] = String(result.metadata.file_size);
  }
  return new Response(result.value, { headers });
}

/** Entry point for every streaming route. */
export async function handleStreaming(request: Request, env: Env, url: URL): Promise<Response> {
  const method = request.method.toUpperCase();
  const segments = segmentsOf(url.pathname);

  try {
    if (method === 'PUT' && segments.length === 6 && segments[1] === 'ciphers') {
      return await handleAttachmentUpload(
        request,
        env,
        url,
        segments[2] as string,
        segments[4] as string,
      );
    }
    if (method === 'GET' && segments.length === 6 && segments[1] === 'ciphers') {
      return await handleAttachmentDownload(env, url, segments[2] as string, segments[4] as string);
    }

    // Send file transfers
    if (method === 'PUT' && segments.length === 6 && segments[1] === 'sends') {
      return await handleSendUpload(
        request,
        env,
        url,
        segments[2] as string,
        segments[4] as string,
      );
    }
    if (method === 'GET' && segments.length === 4 && segments[1] === 'sends') {
      return await handleSendDownload(env, url, segments[2] as string, segments[3] as string);
    }

    return errorResponse(404, 'Not found');
  } catch (error) {
    return toAppErrorResponse(error);
  }
}
