import type { Context } from 'hono';
import { z } from 'zod';

import { DEVICE_TYPE, deviceTypeDisplayName, deviceTypeFromString } from '../auth/device';
import { constantTimeEqual } from '../auth/password';
import { getDb, nowString } from '../db/client';
import { AppError } from '../errors';
import { readJson } from '../http/body';
import { jsonResponse } from '../http/rawJson';
import { UPDATE_TYPE } from '../notifications/frames';
import { publishAnonymousUpdate, publishAuthUpdate } from '../notifications/publish';
import type { AppEnv } from '../types';

/** Pending auth requests are only listed for 5 minutes after creation. */
const EXPIRY_MINUTES = 5;

const createSchema = z.object({
  accessCode: z.string(),
  deviceIdentifier: z.string(),
  email: z.string(),
  publicKey: z.string(),
});

const updateSchema = z.object({
  deviceIdentifier: z.string(),
  key: z.string(),
  masterPasswordHash: z.string().nullish(),
  requestApproved: z.boolean(),
});

interface AuthRequestRow {
  id: string;
  user_id: string;
  request_device_identifier: string;
  device_type: number;
  request_ip: string;
  response_device_id: string | null;
  access_code: string;
  public_key: string;
  enc_key: string | null;
  master_password_hash: string | null;
  approved: number | null;
  creation_date: string;
  response_date: string | null;
  authentication_date: string | null;
}

const COLUMNS =
  'id, user_id, request_device_identifier, device_type, request_ip, response_device_id, access_code, public_key, enc_key, master_password_hash, approved, creation_date, response_date, authentication_date';

function badRequest(): AppError {
  return AppError.badRequest("AuthRequest doesn't exist");
}

/** `request_device_type_from_headers` (HTTP header names are case-insensitive). */
function deviceTypeFromHeaders(c: Context<AppEnv>): number {
  for (const name of ['device-type', 'x-device-type']) {
    const value = c.req.header(name)?.trim();
    if (value !== undefined && value.length > 0) {
      return deviceTypeFromString(value);
    }
  }
  return DEVICE_TYPE.UnknownBrowser;
}

function requestIp(c: Context<AppEnv>): string {
  const value = c.req.header('cf-connecting-ip')?.trim();
  return value !== undefined && value.length > 0 ? value : 'unknown';
}

function toJson(row: AuthRequestRow, origin: string): Record<string, unknown> {
  return {
    id: row.id,
    publicKey: row.public_key,
    requestDeviceType: deviceTypeDisplayName(row.device_type),
    requestIpAddress: row.request_ip,
    key: row.enc_key,
    masterPasswordHash: row.master_password_hash,
    creationDate: row.creation_date,
    responseDate: row.response_date,
    requestApproved: row.approved === 1,
    origin,
    object: 'auth-request',
  };
}

async function findById(c: Context<AppEnv>, id: string): Promise<AuthRequestRow | null> {
  return getDb(c.env)
    .prepare(`SELECT ${COLUMNS} FROM auth_requests WHERE id = ?1`)
    .bind(id)
    .first<AuthRequestRow>();
}

async function findByIdAndUser(
  c: Context<AppEnv>,
  id: string,
  userId: string,
): Promise<AuthRequestRow | null> {
  return getDb(c.env)
    .prepare(`SELECT ${COLUMNS} FROM auth_requests WHERE id = ?1 AND user_id = ?2`)
    .bind(id, userId)
    .first<AuthRequestRow>();
}

/** `POST /api/auth-requests` */
export async function postAuthRequestHandler(c: Context<AppEnv>): Promise<Response> {
  const payload = await readJson(c.req.raw, createSchema);
  const db = getDb(c.env);

  const user = await db
    .prepare('SELECT id FROM users WHERE email = ?1')
    .bind(payload.email.toLowerCase())
    .first<{ id: string }>();
  if (user === null) throw badRequest();

  const requestDeviceType = deviceTypeFromHeaders(c);
  const device = await db
    .prepare('SELECT identifier, type FROM devices WHERE identifier = ?1 AND user_id = ?2')
    .bind(payload.deviceIdentifier, user.id)
    .first<{ identifier: string; type: number }>();

  if (device === null || device.type !== requestDeviceType) {
    throw badRequest();
  }

  const now = nowString();
  const row: AuthRequestRow = {
    id: crypto.randomUUID(),
    user_id: user.id,
    request_device_identifier: payload.deviceIdentifier,
    device_type: requestDeviceType,
    request_ip: requestIp(c),
    response_device_id: null,
    access_code: payload.accessCode,
    public_key: payload.publicKey,
    enc_key: null,
    master_password_hash: null,
    approved: null,
    creation_date: now,
    response_date: null,
    authentication_date: null,
  };

  await db
    .prepare(
      `INSERT INTO auth_requests (${COLUMNS}) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)`,
    )
    .bind(
      row.id,
      row.user_id,
      row.request_device_identifier,
      row.device_type,
      row.request_ip,
      row.response_device_id,
      row.access_code,
      row.public_key,
      row.enc_key,
      row.master_password_hash,
      row.approved,
      row.creation_date,
      row.response_date,
      row.authentication_date,
    )
    .run();

  publishAuthUpdate(c.env, user.id, UPDATE_TYPE.AuthRequest, row.id, payload.deviceIdentifier);

  return jsonResponse(toJson(row, c.get('baseUrl')));
}
export async function listAuthRequestsHandler(c: Context<AppEnv>): Promise<Response> {
  const cutoff = new Date(Date.now() - EXPIRY_MINUTES * 60_000).toISOString();
  const rows = await getDb(c.env)
    .prepare(
      `SELECT ${COLUMNS} FROM auth_requests
        WHERE user_id = ?1 AND approved IS NULL AND creation_date > ?2
        ORDER BY creation_date DESC`,
    )
    .bind(c.get('claims').sub, cutoff)
    .all<AuthRequestRow>();

  return jsonResponse({
    data: (rows.results ?? []).map((row) => toJson(row, c.get('baseUrl'))),
    continuationToken: null,
    object: 'list',
  });
}

/** `GET /api/auth-requests/{id}` */
export async function getAuthRequestHandler(c: Context<AppEnv>): Promise<Response> {
  const row = await findByIdAndUser(c, c.req.param('id') ?? '', c.get('claims').sub);
  if (row === null) throw badRequest();
  return jsonResponse(toJson(row, c.get('baseUrl')));
}

/** `PUT /api/auth-requests/{id}` */
export async function putAuthRequestHandler(c: Context<AppEnv>): Promise<Response> {
  const payload = await readJson(c.req.raw, updateSchema);
  const claims = c.get('claims');
  const row = await findByIdAndUser(c, c.req.param('id') ?? '', claims.sub);
  if (row === null) throw badRequest();

  if (claims.device !== payload.deviceIdentifier) throw badRequest();

  if (row.approved !== null) {
    throw AppError.badRequest('An authentication request with the same device already exists');
  }

  const db = getDb(c.env);
  const now = nowString();

  if (payload.requestApproved) {
    const updated: AuthRequestRow = {
      ...row,
      approved: 1,
      enc_key: payload.key,
      master_password_hash: payload.masterPasswordHash ?? null,
      response_device_id: payload.deviceIdentifier,
      response_date: now,
    };
    await db
      .prepare(
        'UPDATE auth_requests SET approved = ?1, enc_key = ?2, master_password_hash = ?3, response_device_id = ?4, response_date = ?5 WHERE id = ?6',
      )
      .bind(
        updated.approved,
        updated.enc_key,
        updated.master_password_hash,
        updated.response_device_id,
        updated.response_date,
        row.id,
      )
      .run();

    // The auth-request id doubles as the anonymous fan-out token.
    publishAnonymousUpdate(c.env, row.id, row.user_id, row.id);
    publishAuthUpdate(c.env, row.user_id, UPDATE_TYPE.AuthRequestResponse, row.id, claims.device);

    return jsonResponse(toJson(updated, c.get('baseUrl')));
  }

  await db.prepare('DELETE FROM auth_requests WHERE id = ?1').bind(row.id).run();
  return jsonResponse(toJson({ ...row, response_date: now }, c.get('baseUrl')));
}

/** `GET /api/auth-requests/{id}/response?code=` — unauthenticated. */
export async function getAuthRequestResponseHandler(c: Context<AppEnv>): Promise<Response> {
  const row = await findById(c, c.req.param('id') ?? '');
  if (row === null) throw badRequest();

  const code = c.req.query('code') ?? '';
  if (
    row.device_type !== deviceTypeFromHeaders(c) ||
    row.request_ip !== requestIp(c) ||
    !constantTimeEqual(row.access_code, code)
  ) {
    throw badRequest();
  }

  return jsonResponse(toJson(row, c.get('baseUrl')));
}
