import { bytesToBase64Url } from '../auth/base64';
import { bind, type Db, nowString } from './client';

/** Device row, mirroring `sql/schema.sql`. */
export interface DeviceRow {
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

const COLUMNS =
  'identifier, user_id, name, type, push_uuid, push_token, refresh_token, twofactor_remember, created_at, updated_at';

/** 64 random bytes as URL_SAFE base64 with padding (88 characters). */
export function generateDeviceRefreshToken(): string {
  const bytes = new Uint8Array(64);
  crypto.getRandomValues(bytes);
  return bytesToBase64Url(bytes);
}

export async function findByIdentifierAndUser(
  db: Db,
  identifier: string,
  userId: string,
): Promise<DeviceRow | null> {
  return db
    .prepare(`SELECT ${COLUMNS} FROM devices WHERE identifier = ?1 AND user_id = ?2`)
    .bind(identifier, userId)
    .first<DeviceRow>();
}

/**
 * Look up the device for (identifier, user), creating it when missing.
 *
 * A device row — and therefore its refresh token — is created *before* 2FA is
 * verified, so a failed second factor still leaves the device behind. This
 * matches the Rust implementation and is relied on by the login flow.
 */
export async function getOrCreateDevice(
  db: Db,
  identifier: string,
  userId: string,
  name: string,
  type: number,
): Promise<DeviceRow> {
  const existing = await findByIdentifierAndUser(db, identifier, userId);
  const now = nowString();

  if (existing !== null) {
    if (existing.name !== name || existing.type !== type) {
      await bind(
        db.prepare(
          'UPDATE devices SET name = ?1, type = ?2, updated_at = ?3 WHERE identifier = ?4 AND user_id = ?5',
        ),
        [name, type, now, identifier, userId],
      ).run();
      return { ...existing, name, type, updated_at: now };
    }
    return existing;
  }

  const device: DeviceRow = {
    identifier,
    user_id: userId,
    name,
    type,
    push_uuid: null,
    push_token: null,
    refresh_token: generateDeviceRefreshToken(),
    twofactor_remember: null,
    created_at: now,
    updated_at: now,
  };

  await bind(
    db.prepare(`INSERT INTO devices (${COLUMNS}) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)`),
    [
      device.identifier,
      device.user_id,
      device.name,
      device.type,
      device.push_uuid,
      device.push_token,
      device.refresh_token,
      device.twofactor_remember,
      device.created_at,
      device.updated_at,
    ],
  ).run();

  return device;
}

/** Bump `updated_at` without changing any other column. */
export async function touchDevice(
  db: Db,
  identifier: string,
  userId: string,
  now: string,
): Promise<void> {
  await bind(
    db.prepare('UPDATE devices SET updated_at = ?1 WHERE identifier = ?2 AND user_id = ?3'),
    [now, identifier, userId],
  ).run();
}

/** Persist or clear the remember-2FA token for a device. */
export async function setTwoFactorRemember(
  db: Db,
  identifier: string,
  userId: string,
  value: string | null,
  now: string,
): Promise<void> {
  await bind(
    db.prepare(
      'UPDATE devices SET twofactor_remember = ?1, updated_at = ?2 WHERE identifier = ?3 AND user_id = ?4',
    ),
    [value, now, identifier, userId],
  ).run();
}

/** Delete every device for a user (used by security-stamp rotation). */
export async function deleteUserDevices(db: Db, userId: string): Promise<void> {
  await bind(db.prepare('DELETE FROM devices WHERE user_id = ?1'), [userId]).run();
}
