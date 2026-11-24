import type { Context } from 'hono';
import { z } from 'zod';

import { base64UrlNoPadToBytes, base64UrlToBytes } from '../auth/base64';
import { getDb, nowString } from '../db/client';
import { AppError } from '../errors';
import { readJson } from '../http/body';
import { jsonResponse } from '../http/rawJson';
import { pushConfig, registerPushDevice, unregisterPushDevice } from '../notifications/push';
import type { AppEnv } from '../types';

const pushTokenSchema = z.object({ pushToken: z.string() });

interface DeviceRow {
  identifier: string;
  user_id: string;
  name: string;
  type: number;
  push_uuid: string | null;
  push_token: string | null;
  refresh_token: string;
  twofactor_remember: string | null;
  created_at: string;
  updated_at: string;
}

interface PendingAuthRequestRow {
  id: string;
  creation_date: string;
  request_device_identifier: string;
}

/** `Device::to_json` — note `id` and `identifier` are the same value. */
export function deviceToJson(device: DeviceRow): Record<string, unknown> {
  return {
    id: device.identifier,
    name: device.name,
    type: device.type,
    identifier: device.identifier,
    creationDate: device.created_at,
    isTrusted: false,
    encryptedPublicKey: null,
    encryptedUserKey: null,
    object: 'device',
  };
}

function requiredHeader(c: Context<AppEnv>, name: string): string {
  const value = c.req.header(name)?.trim();
  if (value === undefined || value.length === 0) {
    throw AppError.badRequest(`Missing ${name} header`);
  }
  return value;
}

function decodeBase64UrlEmail(encoded: string): string {
  let bytes: Uint8Array;
  try {
    bytes = base64UrlNoPadToBytes(encoded);
  } catch {
    try {
      bytes = base64UrlToBytes(encoded);
    } catch {
      throw AppError.badRequest('Invalid X-Request-Email header');
    }
  }

  try {
    return new TextDecoder('utf-8', { fatal: true, ignoreBOM: false }).decode(bytes);
  } catch {
    throw AppError.badRequest('Invalid X-Request-Email header');
  }
}

async function findDevice(
  c: Context<AppEnv>,
  identifier: string,
  userId: string,
): Promise<DeviceRow | null> {
  return getDb(c.env)
    .prepare('SELECT * FROM devices WHERE identifier = ?1 AND user_id = ?2')
    .bind(identifier, userId)
    .first<DeviceRow>();
}

/** Ownership guard shared by every device mutation. */
async function currentDevice(c: Context<AppEnv>, pathDeviceId: string): Promise<DeviceRow> {
  const claims = c.get('claims');
  if (pathDeviceId !== claims.device) {
    throw AppError.unauthorized('Can only manage the current authenticated device');
  }

  const device = await findDevice(c, claims.device, claims.sub);
  if (device === null) {
    throw AppError.unauthorized('Invalid token');
  }
  return device;
}

/** `GET /api/devices` */
export async function getDevicesHandler(c: Context<AppEnv>): Promise<Response> {
  const db = getDb(c.env);
  const userId = c.get('claims').sub;

  const devices = await db
    .prepare('SELECT * FROM devices WHERE user_id = ?1 ORDER BY updated_at DESC, created_at DESC')
    .bind(userId)
    .all<DeviceRow>();

  const pending = await db
    .prepare(
      'SELECT id, creation_date, request_device_identifier FROM auth_requests WHERE user_id = ?1 AND approved IS NULL',
    )
    .bind(userId)
    .all<PendingAuthRequestRow>();

  const data = (devices.results ?? []).map((device) => {
    const match = (pending.results ?? []).find(
      (row) => row.request_device_identifier === device.identifier,
    );
    return {
      ...deviceToJson(device),
      devicePendingAuthRequest:
        match === undefined ? null : { id: match.id, creationDate: match.creation_date },
    };
  });

  return jsonResponse({ data, continuationToken: null, object: 'list' });
}

/** `GET /api/devices/knowndevice` — unauthenticated. */
export async function getKnownDeviceHandler(c: Context<AppEnv>): Promise<Response> {
  const encodedEmail = requiredHeader(c, 'X-Request-Email');
  const identifier = requiredHeader(c, 'X-Device-Identifier');
  const email = decodeBase64UrlEmail(encodedEmail).toLowerCase();

  const db = getDb(c.env);
  const user = await db
    .prepare('SELECT id FROM users WHERE email = ?1')
    .bind(email)
    .first<{ id: string }>();

  if (user === null) {
    return jsonResponse(false);
  }

  return jsonResponse((await findDevice(c, identifier, user.id)) !== null);
}

/** `GET /api/devices/identifier/{device_id}` */
export async function getDeviceHandler(c: Context<AppEnv>): Promise<Response> {
  const deviceId = c.req.param('device_id') ?? '';
  const device = await findDevice(c, deviceId, c.get('claims').sub);
  if (device === null) {
    throw AppError.notFound('Device not found');
  }
  return jsonResponse(deviceToJson(device));
}

async function upsertPushToken(c: Context<AppEnv>): Promise<Response> {
  const deviceId = c.req.param('device_id') ?? '';
  const payload = await readJson(c.req.raw, pushTokenSchema);
  const pushToken = payload.pushToken.trim();
  if (pushToken.length === 0) {
    throw AppError.badRequest('Missing pushToken');
  }

  const device = await currentDevice(c, deviceId);
  // Identical token with a completed relay registration is a no-op.
  if (device.push_token === pushToken && device.push_uuid !== null) {
    return jsonResponse({});
  }

  await getDb(c.env)
    .prepare(
      'UPDATE devices SET push_token = ?1, updated_at = ?2 WHERE identifier = ?3 AND user_id = ?4',
    )
    .bind(pushToken, nowString(), device.identifier, device.user_id)
    .run();

  // Register with the relay so mobile clients can receive notifications.
  const cfg = pushConfig(c.env);
  if (cfg !== null) {
    try {
      const pushUuid = await registerPushDevice(c.env, cfg, {
        identifier: device.identifier,
        userId: device.user_id,
        type: device.type,
        pushUuid: device.push_uuid,
        pushToken,
      });
      await getDb(c.env)
        .prepare(
          'UPDATE devices SET push_uuid = ?1, updated_at = ?2 WHERE identifier = ?3 AND user_id = ?4',
        )
        .bind(pushUuid, nowString(), device.identifier, device.user_id)
        .run();
    } catch (error) {
      console.warn('[devices] push registration failed', error);
    }
  }

  return jsonResponse({});
}

async function clearPushToken(c: Context<AppEnv>): Promise<Response> {
  const deviceId = c.req.param('device_id') ?? '';
  const device = await currentDevice(c, deviceId);

  const cfg = pushConfig(c.env);
  if (cfg !== null && device.push_uuid !== null) {
    await unregisterPushDevice(cfg, device.push_uuid);
  }

  await getDb(c.env)
    .prepare(
      'UPDATE devices SET push_token = NULL, push_uuid = NULL, updated_at = ?1 WHERE identifier = ?2 AND user_id = ?3',
    )
    .bind(nowString(), device.identifier, device.user_id)
    .run();

  return jsonResponse({});
}

export const postDeviceTokenHandler = upsertPushToken;
export const putDeviceTokenHandler = upsertPushToken;
export const putClearDeviceTokenHandler = clearPushToken;
export const postClearDeviceTokenHandler = clearPushToken;

/**
 * `DELETE /api/devices/{id}` — revoke a single session.
 *
 * Deleting the row is enough: the auth middleware re-checks that the device
 * referenced by the token still exists, so the next request from that device
 * gets a 401. No notification is published — the hub tags connections per user,
 * not per device, so a `LogOut` frame would kick every session.
 */
export async function deleteDeviceHandler(c: Context<AppEnv>): Promise<Response> {
  const identifier = c.req.param('id') ?? c.req.param('device_id') ?? '';
  const claims = c.get('claims');

  const db = getDb(c.env);
  const device = await db
    .prepare('SELECT push_uuid FROM devices WHERE identifier = ?1 AND user_id = ?2')
    .bind(identifier, claims.sub)
    .first<{ push_uuid: string | null }>();

  if (device === null) {
    throw AppError.notFound('Device not found');
  }

  // Best effort: a stale relay registration is harmless, a failed call is not
  // a reason to keep the session alive.
  const cfg = pushConfig(c.env);
  if (cfg !== null && device.push_uuid !== null) {
    try {
      await unregisterPushDevice(cfg, device.push_uuid);
    } catch (error) {
      console.warn('[devices] push unregister failed', error);
    }
  }

  await db
    .prepare('DELETE FROM devices WHERE identifier = ?1 AND user_id = ?2')
    .bind(identifier, claims.sub)
    .run();

  return jsonResponse(null);
}
