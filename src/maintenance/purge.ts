/**
 * Cron maintenance tasks, mirroring `src/handlers/purge.rs` + `src/lib.rs`.
 *
 * The Worker's `scheduled()` handler runs these five purges in order. Every task
 * is isolated: a failure is logged and the remaining tasks still run, which is
 * what `log_purge_result` does in the Rust implementation.
 */

import { type Db, getDb, nowString } from '../db/client';
import {
  listAttachmentKeysForSoftDeletedBefore,
  listExpiredSendKeys,
  listStalePendingSendKeys,
  sendStorageKeys,
} from '../db/storageKeys';
import type { Env } from '../env';
import { publishUserUpdate } from '../notifications/publish';
import { attachmentsEnabled, deleteStorageObjects } from '../storage';

/** Days a soft-deleted cipher is kept before it is purged for good. */
const DEFAULT_PURGE_DAYS = 30;
/** Unfinished attachment uploads are dropped after this long. */
const PENDING_RETENTION_DAYS = 1;
/** Auth requests are only meaningful for a few minutes. */
const AUTH_REQUEST_RETENTION_MINUTES = 15;

/** `UpdateType::SyncVault` — clients re-fetch the vault after a purge. */
const SYNC_VAULT = 5;

const MS_PER_DAY = 86_400_000;
const MS_PER_MINUTE = 60_000;

export interface PurgeReport {
  pendingAttachments: number;
  deletedCiphers: number;
  stalePendingSends: number;
  expiredSends: number;
  expiredAuthRequests: number;
}

function isoBefore(milliseconds: number): string {
  return new Date(Date.now() - milliseconds).toISOString();
}

/**
 * `TRASH_AUTO_DELETE_DAYS` with the reference implementation's semantics: any
 * integer is accepted (a negative value disables auto-purge), and anything
 * unparsable falls back to the default.
 */
export function trashAutoDeleteDays(env: Env): number {
  const raw = env.TRASH_AUTO_DELETE_DAYS;
  if (raw === undefined) return DEFAULT_PURGE_DAYS;

  const trimmed = raw.trim();
  if (!/^-?\d+$/.test(trimmed)) return DEFAULT_PURGE_DAYS;

  const parsed = Number(trimmed);
  return Number.isSafeInteger(parsed) ? parsed : DEFAULT_PURGE_DAYS;
}

async function countRows(db: Db, sql: string, ...values: unknown[]): Promise<number> {
  const row = await db
    .prepare(sql)
    .bind(...values)
    .first<{ count: number }>();
  return row?.count ?? 0;
}

/** Drop attachment uploads that never completed (older than one day). */
export async function purgeStalePendingAttachments(env: Env): Promise<number> {
  const db = getDb(env);
  const cutoff = isoBefore(PENDING_RETENTION_DAYS * MS_PER_DAY);

  const count = await countRows(
    db,
    'SELECT COUNT(*) AS count FROM attachments_pending WHERE created_at < ?1',
    cutoff,
  );
  if (count === 0) return 0;

  await db.prepare('DELETE FROM attachments_pending WHERE created_at < ?1').bind(cutoff).run();
  return count;
}

/**
 * Permanently remove ciphers that have sat in the trash past the retention
 * window, together with their attachment objects, and bump each affected user's
 * revision date so clients resync.
 */
export async function purgeDeletedCiphers(env: Env): Promise<number> {
  const days = trashAutoDeleteDays(env);
  if (days <= 0) return 0;

  const db = getDb(env);
  const cutoff = isoBefore(days * MS_PER_DAY);
  const now = nowString();

  const affected = await db
    .prepare(
      `SELECT DISTINCT user_id FROM ciphers
       WHERE deleted_at IS NOT NULL AND deleted_at < ?1 AND user_id IS NOT NULL`,
    )
    .bind(cutoff)
    .all<{ user_id: string }>();

  const count = await countRows(
    db,
    'SELECT COUNT(*) AS count FROM ciphers WHERE deleted_at IS NOT NULL AND deleted_at < ?1',
    cutoff,
  );
  if (count === 0) return 0;

  if (attachmentsEnabled(env)) {
    await deleteStorageObjects(env, await listAttachmentKeysForSoftDeletedBefore(db, cutoff));
  }

  await db
    .prepare('DELETE FROM ciphers WHERE deleted_at IS NOT NULL AND deleted_at < ?1')
    .bind(cutoff)
    .run();

  for (const { user_id: userId } of affected.results ?? []) {
    await db.prepare('UPDATE users SET updated_at = ?1 WHERE id = ?2').bind(now, userId).run();
    publishUserUpdate(env, userId, SYNC_VAULT, now);
  }

  return count;
}

/** Drop file Sends whose upload never completed (older than one day). */
export async function purgeStalePendingSends(env: Env): Promise<number> {
  const db = getDb(env);
  const cutoff = isoBefore(PENDING_RETENTION_DAYS * MS_PER_DAY);

  if (attachmentsEnabled(env)) {
    await deleteStorageObjects(env, sendStorageKeys(await listStalePendingSendKeys(db, cutoff)));
  }

  const count = await countRows(
    db,
    'SELECT COUNT(*) AS count FROM sends_pending WHERE created_at < ?1',
    cutoff,
  );
  if (count === 0) return 0;

  await db.prepare('DELETE FROM sends_pending WHERE created_at < ?1').bind(cutoff).run();
  return count;
}

/** Drop Sends past their deletion date, including their file objects. */
export async function purgeExpiredSends(env: Env): Promise<number> {
  const db = getDb(env);
  const now = nowString();

  const expired = await listExpiredSendKeys(db, now);
  if (expired.length === 0) return 0;

  if (attachmentsEnabled(env)) {
    await deleteStorageObjects(env, sendStorageKeys(expired));
  }

  await db.prepare('DELETE FROM sends WHERE deletion_date <= ?1').bind(now).run();

  // Bump the revision date so the owner's clients stop showing the dead Send.
  const owners = new Set(expired.map((row) => row.user_id));
  for (const userId of owners) {
    await db.prepare('UPDATE users SET updated_at = ?1 WHERE id = ?2').bind(now, userId).run();
  }

  return expired.length;
}

/** Drop auth requests that were never answered. */
export async function purgeExpiredAuthRequests(env: Env): Promise<number> {
  const db = getDb(env);
  const cutoff = isoBefore(AUTH_REQUEST_RETENTION_MINUTES * MS_PER_MINUTE);

  const result = await db
    .prepare('DELETE FROM auth_requests WHERE creation_date < ?1')
    .bind(cutoff)
    .run();

  return result.meta?.changes ?? 0;
}

async function runTask(name: string, task: () => Promise<number>): Promise<number> {
  try {
    const purged = await task();
    console.log(`[cron] ${name}: purged ${purged}`);
    return purged;
  } catch (error) {
    console.error(`[cron] ${name}: failed`, error);
    return 0;
  }
}

/**
 * Run every purge task in the same order as `lib.rs`:
 * pending attachments → deleted ciphers → stale pending sends → expired sends →
 * expired auth requests.
 */
export async function runScheduledPurges(env: Env): Promise<PurgeReport> {
  return {
    pendingAttachments: await runTask('purge_stale_pending_attachments', () =>
      purgeStalePendingAttachments(env),
    ),
    deletedCiphers: await runTask('purge_deleted_ciphers', () => purgeDeletedCiphers(env)),
    stalePendingSends: await runTask('purge_stale_pending_sends', () =>
      purgeStalePendingSends(env),
    ),
    expiredSends: await runTask('purge_expired_sends', () => purgeExpiredSends(env)),
    expiredAuthRequests: await runTask('purge_expired_auth_requests', () =>
      purgeExpiredAuthRequests(env),
    ),
  };
}
