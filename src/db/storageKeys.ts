/**
 * Queries that return **storage object keys** (not rows) for cleanup paths.
 *
 * Mirrors the `list_attachment_keys_*` / `storage_keys_*` helpers in
 * `src/handlers/attachments.rs` and `src/models/send.rs`. Keeping them here
 * avoids a cycle: handlers import these, and the purge tasks in
 * `src/maintenance/purge.ts` use the same functions.
 */

import { attachmentStorageKey, sendStorageKey } from '../storage';
import type { Db } from './client';

/** `sends.type` value for file Sends. */
export const SEND_TYPE_FILE = 1;

interface AttachmentKeyRow {
  cipher_id: string;
  id: string;
}

export interface SendKeyRow {
  id: string;
  type: number;
  data: string;
  user_id: string;
}

function placeholders(count: number, startAt: number): string {
  return Array.from({ length: count }, (_, index) => `?${startAt + index}`).join(', ');
}

function attachmentKeys(rows: readonly AttachmentKeyRow[]): string[] {
  return rows.map((row) => attachmentStorageKey(row.cipher_id, row.id));
}

/**
 * Storage keys for the attachments of `cipherIds`, restricted to `userId`.
 *
 * The user filter is what stops a crafted id list from deleting another user's
 * blobs (`ciphers.rs` does the same with `AND c.user_id = ?3`).
 */
export async function listAttachmentKeysForCiphers(
  db: Db,
  userId: string,
  cipherIds: readonly string[],
): Promise<string[]> {
  if (cipherIds.length === 0) return [];

  const rows = await db
    .prepare(
      `SELECT a.cipher_id, a.id FROM attachments a JOIN ciphers c ON a.cipher_id = c.id
       WHERE c.user_id = ?1 AND c.id IN (${placeholders(cipherIds.length, 2)})`,
    )
    .bind(userId, ...cipherIds)
    .all<AttachmentKeyRow>();

  return attachmentKeys(rows.results ?? []);
}

/** Storage keys for every attachment the user owns. */
export async function listAttachmentKeysForUser(db: Db, userId: string): Promise<string[]> {
  const rows = await db
    .prepare(
      `SELECT a.cipher_id, a.id FROM attachments a JOIN ciphers c ON a.cipher_id = c.id
       WHERE c.user_id = ?1`,
    )
    .bind(userId)
    .all<AttachmentKeyRow>();

  return attachmentKeys(rows.results ?? []);
}

/** Storage keys for attachments of ciphers soft-deleted before `cutoff`. */
export async function listAttachmentKeysForSoftDeletedBefore(
  db: Db,
  cutoff: string,
): Promise<string[]> {
  const rows = await db
    .prepare(
      `SELECT a.cipher_id, a.id FROM attachments a JOIN ciphers c ON a.cipher_id = c.id
       WHERE c.deleted_at IS NOT NULL AND c.deleted_at < ?1`,
    )
    .bind(cutoff)
    .all<AttachmentKeyRow>();

  return attachmentKeys(rows.results ?? []);
}

/**
 * Turn Send rows into storage keys.
 *
 * Only file Sends have an object, and the file id lives inside the encrypted
 * `data` envelope — a malformed envelope is skipped rather than thrown, exactly
 * like `SendDB::file_id()` returning `None`.
 */
export function sendStorageKeys(rows: readonly SendKeyRow[]): string[] {
  const keys: string[] = [];
  for (const row of rows) {
    if (row.type !== SEND_TYPE_FILE) continue;
    try {
      const parsed = JSON.parse(row.data) as { id?: unknown };
      if (typeof parsed.id === 'string' && parsed.id.length > 0) {
        keys.push(sendStorageKey(row.id, parsed.id));
      }
    } catch {
      // Malformed data: nothing to clean up.
    }
  }
  return keys;
}

const SEND_KEY_COLUMNS = 'id, type, data, user_id';

/** Every Send the user owns. */
export async function listSendKeysForUser(db: Db, userId: string): Promise<SendKeyRow[]> {
  const rows = await db
    .prepare(`SELECT ${SEND_KEY_COLUMNS} FROM sends WHERE user_id = ?1`)
    .bind(userId)
    .all<SendKeyRow>();
  return rows.results ?? [];
}

/** Sends past their deletion date (`deletion_date <= now`). */
export async function listExpiredSendKeys(db: Db, now: string): Promise<SendKeyRow[]> {
  const rows = await db
    .prepare(`SELECT ${SEND_KEY_COLUMNS} FROM sends WHERE deletion_date <= ?1`)
    .bind(now)
    .all<SendKeyRow>();
  return rows.results ?? [];
}

/** File Sends whose upload never completed before `cutoff`. */
export async function listStalePendingSendKeys(db: Db, cutoff: string): Promise<SendKeyRow[]> {
  const rows = await db
    .prepare(`SELECT ${SEND_KEY_COLUMNS} FROM sends_pending WHERE created_at < ?1`)
    .bind(cutoff)
    .all<SendKeyRow>();
  return rows.results ?? [];
}

/** Pending file Sends the user never finished uploading. */
export async function listPendingSendKeysForUser(db: Db, userId: string): Promise<SendKeyRow[]> {
  const rows = await db
    .prepare(`SELECT ${SEND_KEY_COLUMNS} FROM sends_pending WHERE user_id = ?1`)
    .bind(userId)
    .all<SendKeyRow>();
  return rows.results ?? [];
}
