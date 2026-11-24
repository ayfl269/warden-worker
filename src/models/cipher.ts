import { z } from 'zod';

/**
 * Storage-side cipher model, mirroring `models/cipher.rs::CipherData`.
 *
 * Only `name` is required; every type-specific field is omitted from the JSON
 * blob when absent. Key order matters because the blob is stored verbatim and
 * returned to clients.
 */

/** Cipher types: 1 Login, 2 SecureNote, 3 Card, 4 Identity, 5 SshKey, 6 BankAccount, 7 DriversLicense, 8 Passport. */
export const CIPHER_TYPE = {
  Login: 1,
  SecureNote: 2,
  Card: 3,
  Identity: 4,
  SshKey: 5,
  BankAccount: 6,
  DriversLicense: 7,
  Passport: 8,
} as const;

/** Serialization order of the flattened type-specific fields. */
const TYPE_FIELD_ORDER = [
  'login',
  'card',
  'identity',
  'secureNote',
  'sshKey',
  'bankAccount',
  'driversLicense',
  'passport',
  'fields',
  'passwordHistory',
  'reprompt',
  'key',
] as const;

export type TypeFieldName = (typeof TYPE_FIELD_ORDER)[number];

export type CipherTypeFields = Partial<Record<TypeFieldName, unknown>>;

export interface CipherDataInput {
  name: string;
  notes?: string | null;
  typeFields: CipherTypeFields;
}

/** Keep only entries that are objects with a string `password`. */
function normalizePasswordHistory(value: unknown): unknown {
  if (!Array.isArray(value)) return [];
  return value.filter(
    (entry) =>
      entry !== null &&
      typeof entry === 'object' &&
      !Array.isArray(entry) &&
      typeof (entry as Record<string, unknown>).password === 'string',
  );
}

/**
 * Build the `data` blob.
 *
 * - `notes` is omitted when null/undefined.
 * - type-specific fields are omitted when undefined (but `null` is preserved).
 * - `passwordHistory` is normalized: non-arrays become `[]`, invalid entries dropped.
 */
export function buildCipherData(input: CipherDataInput): Record<string, unknown> {
  const output: Record<string, unknown> = { name: input.name };

  if (input.notes !== undefined && input.notes !== null) {
    output.notes = input.notes;
  }

  for (const field of TYPE_FIELD_ORDER) {
    const value = input.typeFields[field];
    if (value === undefined) continue;
    output[field] = field === 'passwordHistory' ? normalizePasswordHistory(value) : value;
  }

  return output;
}

// ── request validation ──────────────────────────────────────────────

/** `favorite` accepts a boolean or 0/1. */
const boolOrInt = z
  .union([z.boolean(), z.literal(0), z.literal(1)])
  .transform((value) => value === true || value === 1);

/** `folderId: ""` is treated as null (`deser_opt_nonempty_str`). */
const optionalId = z
  .string()
  .nullish()
  .transform((value) => (value === undefined || value === null || value === '' ? null : value));

const cipherTypeSchema = z.number().int().min(1).max(8);

/** `CipherRequestData` as sent by clients for create/update/import/rotation. */
export const cipherRequestSchema = z.object({
  id: z.string().nullish(),
  folderId: optionalId.optional(),
  organizationId: z.string().nullish(),
  organizationID: z.string().nullish(),
  type: cipherTypeSchema,
  name: z.string(),
  notes: z.string().nullish(),
  favorite: boolOrInt.optional(),
  login: z.unknown().optional(),
  card: z.unknown().optional(),
  identity: z.unknown().optional(),
  secureNote: z.unknown().optional(),
  sshKey: z.unknown().optional(),
  bankAccount: z.unknown().optional(),
  driversLicense: z.unknown().optional(),
  passport: z.unknown().optional(),
  fields: z.unknown().optional(),
  passwordHistory: z.unknown().optional(),
  reprompt: z.number().nullish(),
  key: z.string().nullish(),
  attachments2: z
    .record(z.string(), z.object({ fileName: z.string(), key: z.string() }))
    .optional(),
  lastKnownRevisionDate: z.string().nullish(),
});

export type CipherRequest = z.infer<typeof cipherRequestSchema>;

/** Extract the flattened type fields from a validated request. */
export function typeFieldsOf(request: CipherRequest): CipherTypeFields {
  const fields: CipherTypeFields = {};
  for (const name of TYPE_FIELD_ORDER) {
    const value = (request as Record<string, unknown>)[name];
    if (value !== undefined) fields[name] = value;
  }
  return fields;
}
