import { base64UrlNoPadToBytes, bytesToBase64UrlNoPad } from '../auth/base64';
import { pbkdf2Sha256 } from '../auth/password';
import { AppError } from '../errors';
import { displaySize } from '../storage';

export const SEND_TYPE_TEXT = 0;
export const SEND_TYPE_FILE = 1;

export const SEND_INACCESSIBLE_MSG = 'Send does not exist or is no longer available';

const SEND_PASSWORD_ITERATIONS = 100_000;
const SEND_PASSWORD_SALT_BYTES = 16;
const KEY_LENGTH_BYTES = 32;
const MAX_DELETION_DAYS = 31;

export interface SendRow {
  id: string;
  user_id: string;
  name: string;
  notes: string | null;
  type: number;
  data: string;
  akey: string;
  password_hash: string | null;
  password_salt: string | null;
  password_iter: number | null;
  max_access_count: number | null;
  access_count: number;
  created_at: string;
  updated_at: string;
  expiration_date: string | null;
  deletion_date: string;
  disabled: number;
  hide_email: number;
}

export const SEND_COLUMNS =
  'id, user_id, name, notes, type, data, akey, password_hash, password_salt, password_iter, max_access_count, access_count, created_at, updated_at, expiration_date, deletion_date, disabled, hide_email';

/** Recursively lowercase the first character of every object key. */
export function lowercaseFirstCharKeys(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(lowercaseFirstCharKeys);
  if (value !== null && typeof value === 'object') {
    const output: Record<string, unknown> = {};
    for (const [key, child] of Object.entries(value)) {
      const lower = key.length === 0 ? key : key[0]!.toLowerCase() + key.slice(1);
      output[lower] = lowercaseFirstCharKeys(child);
    }
    return output;
  }
  return value;
}

/** Backfill `size` as a string and `sizeName`, for file sends. */
function normalizeData(data: Record<string, unknown>): Record<string, unknown> {
  const raw = data.size;
  const size =
    typeof raw === 'number' ? raw : typeof raw === 'string' ? Number.parseInt(raw, 10) : Number.NaN;

  if (Number.isFinite(size)) {
    data.size = String(size);
    data.sizeName = displaySize(size);
  }
  return data;
}

function sendData(row: SendRow): Record<string, unknown> {
  let parsed: unknown;
  try {
    parsed = JSON.parse(row.data);
  } catch {
    return {};
  }
  return normalizeData(lowercaseFirstCharKeys(parsed) as Record<string, unknown>);
}

/** Owner-facing `send` object. */
export function sendToJson(row: SendRow): Record<string, unknown> {
  const data = sendData(row);
  return {
    id: row.id,
    accessId: accessIdFromUuid(row.id),
    type: row.type,
    name: row.name,
    notes: row.notes,
    text: row.type === SEND_TYPE_TEXT ? data : null,
    file: row.type === SEND_TYPE_FILE ? data : null,
    key: row.akey,
    maxAccessCount: row.max_access_count,
    accessCount: row.access_count,
    revisionDate: row.updated_at,
    expirationDate: row.expiration_date,
    deletionDate: row.deletion_date,
    disabled: row.disabled !== 0,
    hideEmail: row.hide_email !== 0,
    password: row.password_hash,
    // SendAuthType: Email = 0, Password = 1, None = 2.
    authType: row.password_hash !== null ? 1 : 2,
    object: 'send',
  };
}

/** Anonymous `send-access` object. */
export function sendToAccessJson(
  row: SendRow,
  creatorIdentifier: string | null,
): Record<string, unknown> {
  const data = sendData(row);
  return {
    id: row.id,
    type: row.type,
    name: row.name,
    text: row.type === SEND_TYPE_TEXT ? data : null,
    file: row.type === SEND_TYPE_FILE ? data : null,
    expirationDate: row.expiration_date,
    creatorIdentifier,
    object: 'send-access',
  };
}

// ── accessId ────────────────────────────────────────────────────────

export function accessIdFromUuid(uuid: string): string {
  const clean = uuid.replace(/[^0-9a-fA-F]/g, '');
  if (clean.length === 32) {
    const bytes = new Uint8Array(16);
    for (let index = 0; index < 16; index += 1) {
      bytes[index] = Number.parseInt(clean.slice(index * 2, index * 2 + 2), 16);
    }
    return bytesToBase64UrlNoPad(bytes);
  }
  return bytesToBase64UrlNoPad(new TextEncoder().encode(uuid));
}

export function uuidFromAccessId(accessId: string): string {
  let bytes: Uint8Array;
  try {
    bytes = base64UrlNoPadToBytes(accessId);
  } catch {
    throw AppError.badRequest('Invalid access ID');
  }
  if (bytes.length !== 16) {
    throw AppError.badRequest('Invalid access ID length');
  }
  const hex = [...bytes].map((byte) => byte.toString(16).padStart(2, '0')).join('');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20, 32)}`;
}

// ── password ────────────────────────────────────────────────────────

export interface SendPassword {
  hash: string;
  salt: string;
  iterations: number;
}

export function hashSendPassword(password: string): SendPassword {
  const saltBytes = new Uint8Array(SEND_PASSWORD_SALT_BYTES);
  crypto.getRandomValues(saltBytes);
  const derived = pbkdf2Sha256(
    new TextEncoder().encode(password),
    saltBytes,
    SEND_PASSWORD_ITERATIONS,
  );
  return {
    hash: bytesToBase64UrlNoPad(derived),
    salt: bytesToBase64UrlNoPad(saltBytes),
    iterations: SEND_PASSWORD_ITERATIONS,
  };
}

export function verifySendPassword(row: SendRow, password: string): boolean {
  if (row.password_hash === null || row.password_salt === null || row.password_iter === null) {
    return false;
  }
  const derived = pbkdf2Sha256(
    new TextEncoder().encode(password),
    base64UrlNoPadToBytes(row.password_salt),
    row.password_iter,
  );
  const expected = bytesToBase64UrlNoPad(derived);
  if (expected.length !== row.password_hash.length) return false;
  let difference = 0;
  for (let index = 0; index < expected.length; index += 1) {
    difference |= expected.charCodeAt(index) ^ row.password_hash.charCodeAt(index);
  }
  return difference === 0;
}

/** Returns the password columns to store; empty/absent clears them. */
export function resolveSendPassword(password: string | null | undefined): {
  hash: string | null;
  salt: string | null;
  iterations: number | null;
} {
  if (password === undefined || password === null || password.length === 0) {
    return { hash: null, salt: null, iterations: null };
  }
  const hashed = hashSendPassword(password);
  return { hash: hashed.hash, salt: hashed.salt, iterations: hashed.iterations };
}

// ── access rules ────────────────────────────────────────────────────

export function validateSendAccess(row: SendRow, now: string): void {
  if (row.disabled !== 0) throw AppError.notFound(SEND_INACCESSIBLE_MSG);
  if (row.deletion_date <= now) throw AppError.notFound(SEND_INACCESSIBLE_MSG);
  if (row.expiration_date !== null && row.expiration_date <= now) {
    throw AppError.notFound(SEND_INACCESSIBLE_MSG);
  }
  if (row.max_access_count !== null && row.access_count >= row.max_access_count) {
    throw AppError.notFound(SEND_INACCESSIBLE_MSG);
  }
}

// ── dates ───────────────────────────────────────────────────────────

function normalizeDate(value: string): string {
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) {
    throw AppError.badRequest('Invalid date');
  }
  return parsed.toISOString();
}

export interface SendDates {
  deletionDate: string;
  expirationDate: string | null;
}

export function validateSendDates(
  deletionDate: string,
  expirationDate: string | null | undefined,
  nowMs = Date.now(),
): SendDates {
  const deletion = normalizeDate(deletionDate);
  const deletionMs = Date.parse(deletion);

  if (deletionMs <= nowMs) {
    throw AppError.badRequest('Deletion date must be in the future');
  }
  if (deletionMs > nowMs + MAX_DELETION_DAYS * 24 * 3600 * 1000) {
    throw AppError.badRequest('Deletion date must be within 31 days');
  }

  if (expirationDate === undefined || expirationDate === null || expirationDate.length === 0) {
    return { deletionDate: deletion, expirationDate: null };
  }

  const expiration = normalizeDate(expirationDate);
  const expirationMs = Date.parse(expiration);
  if (expirationMs <= nowMs) {
    throw AppError.badRequest('Expiration date must be in the future');
  }
  if (expirationMs > deletionMs) {
    throw AppError.badRequest('Expiration date must be before deletion date');
  }

  return { deletionDate: deletion, expirationDate: expiration };
}
