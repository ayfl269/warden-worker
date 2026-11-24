import type { Env } from './env';

/** R2 takes priority over KV, matching `attachments.rs`. */
export type StorageBackend = { kind: 'r2'; bucket: R2Bucket } | { kind: 'kv'; kv: KVNamespace };

export function getStorageBackend(env: Env): StorageBackend | null {
  if (env.ATTACHMENTS_BUCKET !== undefined) {
    return { kind: 'r2', bucket: env.ATTACHMENTS_BUCKET };
  }
  if (env.ATTACHMENTS_KV !== undefined) {
    return { kind: 'kv', kv: env.ATTACHMENTS_KV };
  }
  return null;
}

export function attachmentsEnabled(env: Env): boolean {
  return getStorageBackend(env) !== null;
}

/** Attachment object key: `{cipher_id}/{attachment_id}`. */
export function attachmentStorageKey(cipherId: string, attachmentId: string): string {
  return `${cipherId}/${attachmentId}`;
}

/** Send file object key: `sends/{send_id}/{file_id}`. */
export function sendStorageKey(sendId: string, fileId: string): string {
  return `sends/${sendId}/${fileId}`;
}

/** KV hard limit for a single value. */
export const KV_MAX_BYTES = 25 * 1024 * 1024;

/** Delete an object; a missing object is not an error. */
export async function deleteStorageObject(env: Env, key: string): Promise<void> {
  const backend = getStorageBackend(env);
  if (backend === null) return;

  try {
    if (backend.kind === 'r2') {
      await backend.bucket.delete(key);
    } else {
      await backend.kv.delete(key);
    }
  } catch (error) {
    console.warn(`[storage] failed to delete '${key}'`, error);
  }
}

/** Store an in-memory payload (legacy multipart upload paths). */
export async function putStorageBytes(
  env: Env,
  key: string,
  bytes: Uint8Array,
  size: number,
): Promise<void> {
  const backend = getStorageBackend(env);
  if (backend === null) {
    throw new Error('storage backend is not configured');
  }

  if (backend.kind === 'r2') {
    await backend.bucket.put(key, bytes);
  } else {
    await backend.kv.put(key, bytes, { metadata: { file_size: size } });
  }
}

/** Human-readable size used by attachment/Send responses. */
export function displaySize(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes < 0) return '0 B';

  const units = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
  let value = bytes;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  return `${value.toFixed(2)} ${units[unit]}`;
}
