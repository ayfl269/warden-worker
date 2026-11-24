import type { Context } from 'hono';
import { z } from 'zod';
import { sendTtl, signSendDownloadToken, signSendFileToken } from '../auth/fileTokens';
import { jwtSecret, SEND_ACCESS_ISSUER, verifyToken } from '../auth/jwt';
import { getDb, nowString } from '../db/client';
import { AppError } from '../errors';
import { readJson } from '../http/body';
import { enforceIpRateLimit } from '../http/limits';
import { jsonResponse } from '../http/rawJson';
import {
  accessIdFromUuid,
  resolveSendPassword,
  SEND_COLUMNS,
  SEND_TYPE_FILE,
  SEND_TYPE_TEXT,
  type SendRow,
  sendToAccessJson,
  sendToJson,
  uuidFromAccessId,
  validateSendAccess,
  validateSendDates,
  verifySendPassword,
} from '../models/send';
import { publishSendUpdate } from '../notifications/publish';
import {
  deleteStorageObject,
  displaySize,
  getStorageBackend,
  KV_MAX_BYTES,
  putStorageBytes,
  sendStorageKey,
} from '../storage';
import type { AppEnv } from '../types';

const SYNC_SEND_CREATE = 12;
const SYNC_SEND_UPDATE = 13;
const SYNC_SEND_DELETE = 14;

const DEFAULT_TEXT_MAX_BYTES = 1_887_436;

const textSendSchema = z.object({
  type: z.number(),
  name: z.string(),
  notes: z.string().nullish(),
  key: z.string(),
  text: z.unknown().optional(),
  file: z.unknown().optional(),
  maxAccessCount: z.number().nullish(),
  deletionDate: z.string(),
  expirationDate: z.string().nullish(),
  disabled: z.boolean().optional(),
  hideEmail: z.boolean().optional(),
  password: z.string().nullish(),
  emails: z.array(z.string()).nullish(),
});

const updateSendSchema = textSendSchema.partial();

async function loadSend(c: Context<AppEnv>, id: string): Promise<SendRow> {
  const row = await getDb(c.env)
    .prepare(`SELECT ${SEND_COLUMNS} FROM sends WHERE id = ?1 AND user_id = ?2`)
    .bind(id, c.get('claims').sub)
    .first<SendRow>();
  if (row === null) throw AppError.badRequest('Send not found');
  return row;
}

function textMaxBytes(c: Context<AppEnv>): number {
  const raw = c.env.SEND_TEXT_MAX_BYTES;
  if (raw === undefined) return DEFAULT_TEXT_MAX_BYTES;
  const parsed = Number.parseInt(raw, 10);
  return Number.isSafeInteger(parsed) ? parsed : DEFAULT_TEXT_MAX_BYTES;
}

/** Strip the client-only `response` key and enforce the text size limit. */
function prepareTextData(c: Context<AppEnv>, text: unknown): string {
  if (text === null || typeof text !== 'object' || Array.isArray(text)) {
    throw AppError.badRequest('Invalid send data');
  }
  const clone = { ...(text as Record<string, unknown>) };
  delete clone.response;

  const serialized = JSON.stringify(clone);
  const bytes = new TextEncoder().encode(serialized).length;
  const limit = textMaxBytes(c);
  if (bytes > limit) {
    throw AppError.badRequest(
      `Text send data exceeds limit (${bytes} bytes). Use file send for larger content.`,
    );
  }
  return serialized;
}

/** `GET /api/sends` */
export async function listSendsHandler(c: Context<AppEnv>): Promise<Response> {
  const rows = await getDb(c.env)
    .prepare(`SELECT ${SEND_COLUMNS} FROM sends WHERE user_id = ?1`)
    .bind(c.get('claims').sub)
    .all<SendRow>();

  return jsonResponse({
    data: (rows.results ?? []).map(sendToJson),
    object: 'list',
    continuationToken: null,
  });
}

/** `POST /api/sends` — text sends only. */
export async function createTextSendHandler(c: Context<AppEnv>): Promise<Response> {
  const payload = await readJson(c.req.raw, textSendSchema);
  if (payload.type !== SEND_TYPE_TEXT) {
    throw AppError.badRequest('Use /api/sends/file/v2 for file sends');
  }

  const dates = validateSendDates(payload.deletionDate, payload.expirationDate);
  const data = prepareTextData(c, payload.text);
  const password = resolveSendPassword(payload.password);

  const claims = c.get('claims');
  const now = nowString();
  const id = crypto.randomUUID();

  await getDb(c.env)
    .prepare(
      `INSERT INTO sends (${SEND_COLUMNS}) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, 0, ?12, ?12, ?13, ?14, ?15, ?16)`,
    )
    .bind(
      id,
      claims.sub,
      payload.name,
      payload.notes ?? null,
      payload.type,
      data,
      payload.key,
      password.hash,
      password.salt,
      password.iterations,
      payload.maxAccessCount ?? null,
      now,
      dates.expirationDate,
      dates.deletionDate,
      payload.disabled ? 1 : 0,
      payload.hideEmail ? 1 : 0,
    )
    .run();

  await getDb(c.env)
    .prepare('UPDATE users SET updated_at = ?1 WHERE id = ?2')
    .bind(now, claims.sub)
    .run();

  publishSendUpdate(c.env, claims.sub, SYNC_SEND_CREATE, id, now, claims.device);

  return jsonResponse(
    sendToJson({
      id,
      user_id: claims.sub,
      name: payload.name,
      notes: payload.notes ?? null,
      type: payload.type,
      data,
      akey: payload.key,
      password_hash: password.hash,
      password_salt: password.salt,
      password_iter: password.iterations,
      max_access_count: payload.maxAccessCount ?? null,
      access_count: 0,
      created_at: now,
      updated_at: now,
      expiration_date: dates.expirationDate,
      deletion_date: dates.deletionDate,
      disabled: payload.disabled ? 1 : 0,
      hide_email: payload.hideEmail ? 1 : 0,
    }),
  );
}

/** `GET /api/sends/{id}` */
export async function getSendHandler(c: Context<AppEnv>): Promise<Response> {
  return jsonResponse(sendToJson(await loadSend(c, c.req.param('send_id') ?? '')));
}

/** `PUT /api/sends/{id}` */
export async function updateSendHandler(c: Context<AppEnv>): Promise<Response> {
  const payload = await readJson(c.req.raw, updateSendSchema);
  const row = await loadSend(c, c.req.param('send_id') ?? '');

  if (payload.emails !== undefined && payload.emails !== null && payload.emails.length > 0) {
    throw AppError.badRequest('Sends with email verification is not supported');
  }
  if (payload.type !== undefined && payload.type !== row.type) {
    throw AppError.badRequest("Sends can't change type");
  }

  const dates = validateSendDates(
    payload.deletionDate ?? row.deletion_date,
    payload.expirationDate === undefined ? row.expiration_date : payload.expirationDate,
  );

  const data = payload.text === undefined ? row.data : prepareTextData(c, payload.text);
  const password =
    payload.password === undefined
      ? { hash: row.password_hash, salt: row.password_salt, iterations: row.password_iter }
      : resolveSendPassword(payload.password);

  const claims = c.get('claims');
  const now = nowString();

  await getDb(c.env)
    .prepare(
      `UPDATE sends SET name = ?1, notes = ?2, data = ?3, akey = ?4, password_hash = ?5, password_salt = ?6,
              password_iter = ?7, max_access_count = ?8, expiration_date = ?9, deletion_date = ?10,
              disabled = ?11, hide_email = ?12, updated_at = ?13
        WHERE id = ?14 AND user_id = ?15`,
    )
    .bind(
      payload.name ?? row.name,
      payload.notes === undefined ? row.notes : payload.notes,
      data,
      payload.key ?? row.akey,
      password.hash,
      password.salt,
      password.iterations,
      payload.maxAccessCount === undefined ? row.max_access_count : payload.maxAccessCount,
      dates.expirationDate,
      dates.deletionDate,
      payload.disabled === undefined ? row.disabled : payload.disabled ? 1 : 0,
      payload.hideEmail === undefined ? row.hide_email : payload.hideEmail ? 1 : 0,
      now,
      row.id,
      claims.sub,
    )
    .run();

  publishSendUpdate(c.env, claims.sub, SYNC_SEND_UPDATE, row.id, now, claims.device);

  return jsonResponse(
    sendToJson({
      ...row,
      name: payload.name ?? row.name,
      notes: payload.notes === undefined ? row.notes : payload.notes,
      data,
      akey: payload.key ?? row.akey,
      password_hash: password.hash,
      password_salt: password.salt,
      password_iter: password.iterations,
      max_access_count:
        payload.maxAccessCount === undefined ? row.max_access_count : payload.maxAccessCount,
      expiration_date: dates.expirationDate,
      deletion_date: dates.deletionDate,
      disabled: payload.disabled === undefined ? row.disabled : payload.disabled ? 1 : 0,
      hide_email: payload.hideEmail === undefined ? row.hide_email : payload.hideEmail ? 1 : 0,
      updated_at: now,
    }),
  );
}

/** `DELETE /api/sends/{id}` */
export async function deleteSendHandler(c: Context<AppEnv>): Promise<Response> {
  const row = await loadSend(c, c.req.param('send_id') ?? '');
  const claims = c.get('claims');
  const now = nowString();

  if (row.type === SEND_TYPE_FILE) {
    try {
      const parsed = JSON.parse(row.data) as { id?: unknown };
      if (typeof parsed.id === 'string') {
        await deleteStorageObject(c.env, sendStorageKey(row.id, parsed.id));
      }
    } catch {
      // Malformed data: nothing to clean up.
    }
  }

  await getDb(c.env)
    .prepare('DELETE FROM sends WHERE id = ?1 AND user_id = ?2')
    .bind(row.id, claims.sub)
    .run();
  await getDb(c.env)
    .prepare('UPDATE users SET updated_at = ?1 WHERE id = ?2')
    .bind(now, claims.sub)
    .run();

  publishSendUpdate(c.env, claims.sub, SYNC_SEND_DELETE, row.id, now, claims.device);

  return jsonResponse('');
}

/** `PUT /api/sends/{id}/remove-password` */
export async function removeSendPasswordHandler(c: Context<AppEnv>): Promise<Response> {
  const row = await loadSend(c, c.req.param('send_id') ?? '');
  const claims = c.get('claims');
  const now = nowString();

  await getDb(c.env)
    .prepare(
      'UPDATE sends SET password_hash = NULL, password_salt = NULL, password_iter = NULL, updated_at = ?1 WHERE id = ?2 AND user_id = ?3',
    )
    .bind(now, row.id, claims.sub)
    .run();

  publishSendUpdate(c.env, claims.sub, SYNC_SEND_UPDATE, row.id, now, claims.device);

  return jsonResponse(
    sendToJson({
      ...row,
      password_hash: null,
      password_salt: null,
      password_iter: null,
      updated_at: now,
    }),
  );
}

async function creatorIdentifier(c: Context<AppEnv>, row: SendRow): Promise<string | null> {
  if (row.hide_email !== 0) return null;
  const user = await getDb(c.env)
    .prepare('SELECT email FROM users WHERE id = ?1')
    .bind(row.user_id)
    .first<{ email: string }>();
  return user?.email ?? null;
}

/** `POST /api/sends/access/{accessId}` — legacy anonymous access. */
export async function accessSendHandler(c: Context<AppEnv>): Promise<Response> {
  const accessId = c.req.param('access_id') ?? '';
  let sendId: string;
  try {
    sendId = uuidFromAccessId(accessId);
  } catch {
    throw AppError.notFound('Send does not exist or is no longer available');
  }

  const db = getDb(c.env);
  const row = await db
    .prepare(`SELECT ${SEND_COLUMNS} FROM sends WHERE id = ?1`)
    .bind(sendId)
    .first<SendRow>();
  if (row === null) throw AppError.notFound('Send does not exist or is no longer available');

  validateSendAccess(row, nowString());

  if (row.password_hash !== null) {
    await enforceIpRateLimit(
      c.env,
      c.req.raw.headers,
      'SEND_ACCESS_RATE_LIMITER',
      'send-access',
      'Too many send password attempts. Please try again later.',
    );

    const body = await readJson(c.req.raw, z.object({ password: z.string().nullish() })).catch(
      () => ({ password: null }),
    );
    const password = body.password;
    if (password === undefined || password === null || password.length === 0) {
      throw AppError.unauthorized('Password not provided');
    }
    if (!verifySendPassword(row, password)) {
      throw AppError.badRequest('Invalid password');
    }
  }

  const now = nowString();
  await db
    .prepare('UPDATE sends SET access_count = access_count + 1, updated_at = ?1 WHERE id = ?2')
    .bind(now, row.id)
    .run();

  return jsonResponse(sendToAccessJson(row, await creatorIdentifier(c, row)));
}

/** `GET /api/sends/{id}` access id helper used by tests/tools. */
const DEFAULT_SEND_MAX_BYTES = 104_857_600;

function sendMaxBytes(c: Context<AppEnv>): number {
  const raw = c.env.SEND_MAX_BYTES;
  if (raw === undefined) return DEFAULT_SEND_MAX_BYTES;
  const parsed = Number.parseInt(raw, 10);
  return Number.isSafeInteger(parsed) ? parsed : DEFAULT_SEND_MAX_BYTES;
}

/** Total bytes used by this user's committed and pending file sends. */
async function sendStorageUsage(c: Context<AppEnv>, userId: string): Promise<number> {
  const db = getDb(c.env);
  const committed = await db
    .prepare(
      "SELECT COALESCE(SUM(CAST(json_extract(data, '$.size') AS INTEGER)), 0) AS total FROM sends WHERE user_id = ?1",
    )
    .bind(userId)
    .first<{ total: number }>();
  const pending = await db
    .prepare(
      "SELECT COALESCE(SUM(CAST(json_extract(data, '$.size') AS INTEGER)), 0) AS total FROM sends_pending WHERE user_id = ?1",
    )
    .bind(userId)
    .first<{ total: number }>();
  return (committed?.total ?? 0) + (pending?.total ?? 0);
}

const fileSendSchema = z.object({
  type: z.number(),
  name: z.string(),
  notes: z.string().nullish(),
  key: z.string(),
  file: z.record(z.string(), z.unknown()),
  fileLength: z.number(),
  maxAccessCount: z.number().nullish(),
  deletionDate: z.string(),
  expirationDate: z.string().nullish(),
  disabled: z.boolean().optional(),
  hideEmail: z.boolean().optional(),
  password: z.string().nullish(),
});

/** `POST /api/sends/file/v2` */
export async function createFileSendV2Handler(c: Context<AppEnv>): Promise<Response> {
  const payload = await readJson(c.req.raw, fileSendSchema);
  if (payload.type !== SEND_TYPE_FILE) {
    throw AppError.badRequest('Send content is not a file');
  }

  const backend = getStorageBackend(c.env);
  if (backend === null) throw AppError.badRequest('File storage is not enabled');

  const dates = validateSendDates(payload.deletionDate, payload.expirationDate);
  if (!Number.isFinite(payload.fileLength)) {
    throw AppError.badRequest('Invalid send length');
  }
  if (payload.fileLength < 0) {
    throw AppError.badRequest("Send size can't be negative");
  }
  if (payload.fileLength > sendMaxBytes(c)) {
    throw AppError.badRequest('File size exceeds send limit');
  }
  if (backend.kind === 'kv' && payload.fileLength > KV_MAX_BYTES) {
    throw AppError.badRequest('File size exceeds KV limit (max 25MB)');
  }

  const claims = c.get('claims');
  const quotaKb = c.env.USER_SEND_LIMIT_KB;
  if (quotaKb !== undefined) {
    const limit = Number.parseInt(quotaKb, 10);
    if (Number.isSafeInteger(limit)) {
      const usage = await sendStorageUsage(c, claims.sub);
      if (usage + payload.fileLength > limit * 1024) {
        throw AppError.badRequest('Send storage limit reached');
      }
    }
  }

  const now = nowString();
  const id = crypto.randomUUID();
  const rawFileId = payload.file.id;
  const fileId =
    typeof rawFileId === 'string' && rawFileId.length > 0 ? rawFileId : crypto.randomUUID();
  const fileName = typeof payload.file.fileName === 'string' ? payload.file.fileName : 'file';
  const data = JSON.stringify({
    id: fileId,
    fileName,
    size: payload.fileLength,
    sizeName: displaySize(payload.fileLength),
  });
  const password = resolveSendPassword(payload.password);

  const pendingRow: SendRow = {
    id,
    user_id: claims.sub,
    name: payload.name,
    notes: payload.notes ?? null,
    type: SEND_TYPE_FILE,
    data,
    akey: payload.key,
    password_hash: password.hash,
    password_salt: password.salt,
    password_iter: password.iterations,
    max_access_count: payload.maxAccessCount ?? null,
    access_count: 0,
    created_at: now,
    updated_at: now,
    expiration_date: dates.expirationDate,
    deletion_date: dates.deletionDate,
    disabled: payload.disabled ? 1 : 0,
    hide_email: payload.hideEmail ? 1 : 0,
  };

  await getDb(c.env)
    .prepare(
      `INSERT INTO sends_pending (${SEND_COLUMNS}) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, 0, ?12, ?12, ?13, ?14, ?15, ?16)`,
    )
    .bind(
      pendingRow.id,
      pendingRow.user_id,
      pendingRow.name,
      pendingRow.notes,
      pendingRow.type,
      pendingRow.data,
      pendingRow.akey,
      pendingRow.password_hash,
      pendingRow.password_salt,
      pendingRow.password_iter,
      pendingRow.max_access_count,
      now,
      pendingRow.expiration_date,
      pendingRow.deletion_date,
      pendingRow.disabled,
      pendingRow.hide_email,
    )
    .run();

  const token = await signSendFileToken(
    c.env,
    { sub: claims.sub, device: claims.device, send_id: id, file_id: fileId },
    sendTtl(c.env),
  );

  return jsonResponse({
    object: 'send-fileUpload',
    url: `${c.get('baseUrl')}/api/sends/${id}/file/${fileId}/azure-upload?token=${token}`,
    fileUploadType: 1,
    sendResponse: sendToJson(pendingRow),
  });
}

/** `POST /api/sends/{send_id}/access/file/{file_id}` — anonymous file access. */
export async function accessFileSendHandler(c: Context<AppEnv>): Promise<Response> {
  const sendId = c.req.param('send_id') ?? '';
  const fileId = c.req.param('file_id') ?? '';
  const db = getDb(c.env);

  const row = await db
    .prepare(`SELECT ${SEND_COLUMNS} FROM sends WHERE id = ?1`)
    .bind(sendId)
    .first<SendRow>();
  if (row === null || row.type !== SEND_TYPE_FILE) {
    throw AppError.notFound('Send does not exist or is no longer available');
  }

  validateSendAccess(row, nowString());

  // A password-protected Send must not hand out a download token to anyone who
  // knows the (recoverable) send id and the file id. Mirrors `access_file_send`
  // in the reference implementation, which gates this endpoint exactly like
  // `access_send`.
  if (row.password_hash !== null) {
    await enforceIpRateLimit(
      c.env,
      c.req.raw.headers,
      'SEND_ACCESS_RATE_LIMITER',
      'send-access',
      'Too many send password attempts. Please try again later.',
    );

    const body = await readJson(c.req.raw, z.object({ password: z.string().nullish() })).catch(
      () => ({ password: null }),
    );
    const password = body.password;
    if (password === undefined || password === null || password.length === 0) {
      throw AppError.unauthorized('Password not provided');
    }
    if (!verifySendPassword(row, password)) {
      throw AppError.badRequest('Invalid password');
    }
  }

  await db
    .prepare('UPDATE sends SET access_count = access_count + 1, updated_at = ?1 WHERE id = ?2')
    .bind(nowString(), row.id)
    .run();

  const token = await signSendDownloadToken(
    c.env,
    { send_id: row.id, file_id: fileId },
    sendTtl(c.env),
  );

  return jsonResponse({
    id: fileId,
    url: `${c.get('baseUrl')}/api/sends/${row.id}/${fileId}?t=${token}`,
    object: 'send-fileDownload',
  });
}

async function sendFromBearer(c: Context<AppEnv>): Promise<SendRow> {
  const header = c.req.header('authorization') ?? '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : '';
  const claims = await verifyToken<{ sub: string; iss?: string }>(
    token,
    jwtSecret(c.env, 'JWT_SECRET'),
    { issuer: SEND_ACCESS_ISSUER, leewaySeconds: 0 },
  );
  if (claims === null || typeof claims.sub !== 'string') {
    throw AppError.unauthorized('Invalid token');
  }

  const row = await getDb(c.env)
    .prepare(`SELECT ${SEND_COLUMNS} FROM sends WHERE id = ?1`)
    .bind(claims.sub)
    .first<SendRow>();
  if (row === null) throw AppError.notFound('Send does not exist or is no longer available');

  validateSendAccess(row, nowString());
  return row;
}

/** `POST /api/sends/access` — Bearer send-access token. */
export async function accessSendWithTokenHandler(c: Context<AppEnv>): Promise<Response> {
  const row = await sendFromBearer(c);
  return jsonResponse(sendToAccessJson(row, await creatorIdentifier(c, row)));
}

/** `POST /api/sends/access/file/{file_id}` — Bearer send-access token. */
export async function accessFileSendWithTokenHandler(c: Context<AppEnv>): Promise<Response> {
  const row = await sendFromBearer(c);
  if (row.type !== SEND_TYPE_FILE) {
    throw AppError.notFound('Send does not exist or is no longer available');
  }

  const fileId = c.req.param('file_id') ?? '';
  const token = await signSendDownloadToken(
    c.env,
    { send_id: row.id, file_id: fileId },
    sendTtl(c.env),
  );

  return jsonResponse({
    id: fileId,
    url: `${c.get('baseUrl')}/api/sends/${row.id}/${fileId}?t=${token}`,
    object: 'send-fileDownload',
  });
}

/** `POST /api/sends/{send_id}/file/{file_id}` — direct multipart file upload. */
export async function uploadFileSendDirectHandler(c: Context<AppEnv>): Promise<Response> {
  const sendId = c.req.param('send_id') ?? '';
  const fileId = c.req.param('file_id') ?? '';
  const claims = c.get('claims');
  const db = getDb(c.env);

  const pending = await db
    .prepare(`SELECT ${SEND_COLUMNS} FROM sends_pending WHERE id = ?1 AND user_id = ?2`)
    .bind(sendId, claims.sub)
    .first<SendRow>();
  if (pending === null) {
    throw AppError.badRequest('Send not found. Unable to save the file.');
  }

  let pendingData: { id?: unknown; size?: unknown } = {};
  try {
    pendingData = JSON.parse(pending.data) as { id?: unknown; size?: unknown };
  } catch {
    pendingData = {};
  }
  if (pendingData.id !== fileId) {
    throw AppError.badRequest('Send file does not match send data.');
  }

  let form: FormData;
  try {
    form = await c.req.raw.formData();
  } catch {
    throw AppError.badRequest('Missing file data');
  }
  const file = form.get('data');
  if (!(file instanceof File)) {
    throw AppError.badRequest('Missing file data');
  }

  const declared = Number(pendingData.size);
  if (!Number.isFinite(declared) || file.size !== declared) {
    throw AppError.badRequest('Send file size does not match.');
  }

  const bytes = new Uint8Array(await file.arrayBuffer());
  try {
    await putStorageBytes(c.env, sendStorageKey(sendId, fileId), bytes, file.size);
  } catch (error) {
    throw AppError.worker(error);
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

  publishSendUpdate(c.env, claims.sub, SYNC_SEND_CREATE, pending.id, now, claims.device);

  return jsonResponse(null);
}

const legacyFileSendSchema = z.object({
  type: z.number(),
  name: z.string(),
  notes: z.string().nullish(),
  key: z.string(),
  file: z.record(z.string(), z.unknown()).nullish(),
  maxAccessCount: z.number().nullish(),
  deletionDate: z.string(),
  expirationDate: z.string().nullish(),
  disabled: z.boolean().optional(),
  hideEmail: z.boolean().optional(),
  password: z.string().nullish(),
});

/** `POST /api/sends/file` — legacy multipart file Send. */
export async function createFileSendLegacyHandler(c: Context<AppEnv>): Promise<Response> {
  const cfg = getStorageBackend(c.env);
  if (cfg === null) throw AppError.badRequest('File storage is not enabled');

  let form: FormData;
  try {
    form = await c.req.raw.formData();
  } catch {
    throw AppError.badRequest('Missing model data');
  }

  const modelRaw = form.get('model');
  if (typeof modelRaw !== 'string' || modelRaw.length === 0) {
    throw AppError.badRequest('Missing model data');
  }

  let model: z.infer<typeof legacyFileSendSchema>;
  try {
    model = legacyFileSendSchema.parse(JSON.parse(modelRaw));
  } catch {
    throw AppError.badRequest('Invalid send data');
  }

  if (model.type !== SEND_TYPE_FILE) {
    throw AppError.badRequest('Send content is not a file');
  }

  const file = form.get('data') ?? form.get('file');
  if (!(file instanceof File)) {
    throw AppError.badRequest('Missing file data');
  }
  if (file.size > sendMaxBytes(c)) {
    throw AppError.badRequest('File size exceeds send limit');
  }

  const quotaKb = c.env.USER_SEND_LIMIT_KB;
  if (quotaKb !== undefined) {
    const limit = Number.parseInt(quotaKb, 10);
    if (Number.isSafeInteger(limit)) {
      const usage = await sendStorageUsage(c, c.get('claims').sub);
      if (usage + file.size > limit * 1024) {
        throw AppError.badRequest('Send storage limit reached');
      }
    }
  }

  const dates = validateSendDates(model.deletionDate, model.expirationDate);
  const claims = c.get('claims');
  const now = nowString();
  const id = crypto.randomUUID();
  const rawFileId = model.file?.id;
  const fileId =
    typeof rawFileId === 'string' && rawFileId.length > 0 ? rawFileId : crypto.randomUUID();
  const fileName = typeof model.file?.fileName === 'string' ? model.file.fileName : file.name;
  const data = JSON.stringify({
    id: fileId,
    fileName,
    size: file.size,
    sizeName: displaySize(file.size),
  });
  const password = resolveSendPassword(model.password);

  const bytes = new Uint8Array(await file.arrayBuffer());
  try {
    await putStorageBytes(c.env, sendStorageKey(id, fileId), bytes, file.size);
  } catch (error) {
    throw AppError.worker(error);
  }

  const row: SendRow = {
    id,
    user_id: claims.sub,
    name: model.name,
    notes: model.notes ?? null,
    type: SEND_TYPE_FILE,
    data,
    akey: model.key,
    password_hash: password.hash,
    password_salt: password.salt,
    password_iter: password.iterations,
    max_access_count: model.maxAccessCount ?? null,
    access_count: 0,
    created_at: now,
    updated_at: now,
    expiration_date: dates.expirationDate,
    deletion_date: dates.deletionDate,
    disabled: model.disabled ? 1 : 0,
    hide_email: model.hideEmail ? 1 : 0,
  };

  await getDb(c.env)
    .prepare(
      `INSERT INTO sends (${SEND_COLUMNS}) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, 0, ?12, ?12, ?13, ?14, ?15, ?16)`,
    )
    .bind(
      row.id,
      row.user_id,
      row.name,
      row.notes,
      row.type,
      row.data,
      row.akey,
      row.password_hash,
      row.password_salt,
      row.password_iter,
      row.max_access_count,
      now,
      row.expiration_date,
      row.deletion_date,
      row.disabled,
      row.hide_email,
    )
    .run();

  publishSendUpdate(c.env, claims.sub, SYNC_SEND_CREATE, row.id, now, claims.device);

  return jsonResponse(sendToJson(row));
}

export { accessIdFromUuid };
