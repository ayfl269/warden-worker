import { jsonResponse } from '../http/rawJson';

/** Cipher row as stored in D1. */
export interface CipherRow {
  id: string;
  user_id: string | null;
  organization_id: string | null;
  type: number;
  data: string;
  favorite: number;
  folder_id: string | null;
  deleted_at: string | null;
  archived_at: string | null;
  created_at: string;
  updated_at: string;
}

/** Attachment entry as returned by `AttachmentResponse`. */
export interface CipherAttachment {
  id: string;
  url: string | null;
  fileName: string;
  size: string;
  sizeName: string;
  key: string | null;
  object: 'attachment';
}

const TYPE_KEYS = [
  'login',
  'secureNote',
  'card',
  'identity',
  'sshKey',
  'bankAccount',
  'driversLicense',
  'passport',
] as const;

/**
 * `Cipher` response (`object: "cipherDetails"`).
 *
 * Field order and null rules mirror the custom `Serialize` impl in
 * `models/cipher.rs`. Every type-specific slot is present; only the one that
 * matches `type` is filled.
 */
export function buildCipherResponse(
  row: CipherRow,
  attachments: CipherAttachment[] | null = null,
  object: 'cipherDetails' | 'cipher' = 'cipherDetails',
): Record<string, unknown> {
  let data: Record<string, unknown> = {};
  try {
    const parsed = JSON.parse(row.data) as unknown;
    if (parsed !== null && typeof parsed === 'object' && !Array.isArray(parsed)) {
      data = parsed as Record<string, unknown>;
    }
  } catch {
    data = {};
  }

  const response: Record<string, unknown> = {
    object,
    id: row.id,
  };

  if (row.user_id !== null) {
    response.userId = row.user_id;
  }

  response.organizationId = row.organization_id;
  response.folderId = row.folder_id;
  response.type = row.type;
  response.favorite = row.favorite !== 0;
  response.edit = true;
  response.viewPassword = true;
  response.permissions = { delete: true, restore: true };
  response.organizationUseTotp = false;
  response.collectionIds = [];
  response.revisionDate = row.updated_at;
  response.creationDate = row.created_at;
  response.deletedDate = row.deleted_at;
  response.archivedDate = row.archived_at;
  response.attachments = attachments;

  response.name = data.name ?? null;
  response.notes = data.notes ?? null;
  response.fields = data.fields ?? [];
  response.passwordHistory = data.passwordHistory ?? [];
  // NOTE: Rust defaults this to the float `0.0`; JSON.stringify emits `0`.
  response.reprompt = data.reprompt ?? 0;
  response.key = data.key ?? null;

  for (const key of TYPE_KEYS) {
    response[key] = null;
  }
  const matching = TYPE_KEYS[row.type - 1];
  if (matching !== undefined) {
    response[matching] = data[matching] ?? null;
  }

  return response;
}

export function cipherListResponse(ciphers: Array<Record<string, unknown>>): Response {
  return jsonResponse({ data: ciphers, object: 'list', continuationToken: null });
}
