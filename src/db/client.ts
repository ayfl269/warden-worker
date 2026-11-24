import type { Env } from '../env';
import { AppError } from '../errors';

/**
 * Unified D1 handle, mirroring `src/db.rs`.
 *
 * Business logic always goes through a session:
 * - `first-primary`      → the first query hits the primary (fresh reads after writes)
 * - `first-unconstrained` → the first query may hit any replica (auth/read paths)
 */
export interface Db {
  prepare(query: string): D1PreparedStatement;
  batch(statements: D1PreparedStatement[]): Promise<D1Result[]>;
}

function sessionDb(env: Env, constraint: 'first-primary' | 'first-unconstrained'): Db {
  const session = env.vault1.withSession(constraint);
  return {
    prepare: (query: string) => session.prepare(query),
    batch: (statements: D1PreparedStatement[]) => session.batch(statements),
  };
}

export function getDb(env: Env): Db {
  return sessionDb(env, 'first-primary');
}

export function getDbUnconstrained(env: Env): Db {
  return sessionDb(env, 'first-unconstrained');
}

/**
 * Timestamp format used everywhere: `%Y-%m-%dT%H:%M:%S%.3fZ`.
 * `Date#toISOString()` produces exactly the same shape.
 */
export function nowString(): string {
  return new Date().toISOString();
}

/** Bind helper: `undefined` is stored as SQL NULL (serde's missing-as-null). */
export function bind(
  statement: D1PreparedStatement,
  values: readonly unknown[],
): D1PreparedStatement {
  return statement.bind(...values.map((value) => (value === undefined ? null : value)));
}

/** Bump `users.updated_at` after any mutation of user-owned data. */
export async function touchUserUpdatedAt(db: Db, userId: string, now: string): Promise<void> {
  try {
    await bind(db.prepare('UPDATE users SET updated_at = ?1 WHERE id = ?2'), [now, userId]).run();
  } catch {
    throw AppError.database();
  }
}

/** Execute statements in batches; `batchSize === 0` runs them all at once. */
export async function executeInBatches(
  db: Db,
  statements: D1PreparedStatement[],
  batchSize: number,
): Promise<void> {
  if (statements.length === 0) return;

  if (batchSize === 0) {
    await db.batch(statements);
    return;
  }

  for (let offset = 0; offset < statements.length; offset += batchSize) {
    await db.batch(statements.slice(offset, offset + batchSize));
  }
}

/** Map D1 JSON parsing failures to 400 while leaving other errors untouched. */
export function mapD1JsonError(error: unknown): AppError {
  const message = error instanceof Error ? error.message : String(error);
  if (message.toLowerCase().includes('malformed json')) {
    return AppError.badRequest('Malformed JSON in request body');
  }
  return AppError.worker(error);
}
