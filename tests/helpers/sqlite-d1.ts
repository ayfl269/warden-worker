import { DatabaseSync } from 'node:sqlite';

/**
 * Test-only D1 adapter backed by `node:sqlite`.
 *
 * The production code only uses a small slice of the D1 API:
 *   env.vault1.withSession(...) -> { prepare, batch }
 *   prepare(sql).bind(...).first<T>() / .all<T>() / .run()
 *
 * This adapter implements exactly that surface over a real SQLite database, so
 * handlers can be exercised end-to-end in plain Node (workerd cannot be spawned
 * in every sandbox).
 */

/** Values accepted by `node:sqlite` parameter binding. */
type SqlValue = null | number | bigint | string | Uint8Array;

class SqliteStatement {
  constructor(
    private readonly db: DatabaseSync,
    private readonly sql: string,
    private readonly params: readonly SqlValue[] = [],
  ) {}

  bind(...values: unknown[]): SqliteStatement {
    return new SqliteStatement(
      this.db,
      this.sql,
      values.map((value) => (value === undefined ? null : (value as SqlValue))),
    );
  }

  async first<T>(_column?: string): Promise<T | null> {
    const row = this.db.prepare(this.sql).get(...this.params);
    return (row ?? null) as T | null;
  }

  async all<T>(): Promise<{ results: T[]; success: true }> {
    const rows = this.db.prepare(this.sql).all(...this.params) as T[];
    return { results: rows, success: true };
  }

  async run(): Promise<{ success: true }> {
    this.db.prepare(this.sql).run(...this.params);
    return { success: true };
  }
}

export interface TestD1 {
  prepare(sql: string): SqliteStatement;
  batch(statements: SqliteStatement[]): Promise<Array<{ success: true }>>;
  withSession(constraint?: string): TestD1;
  exec(sql: string): void;
  close(): void;
  raw: DatabaseSync;
}

export function createTestD1(schema?: string): TestD1 {
  const db = new DatabaseSync(':memory:');
  db.exec('PRAGMA foreign_keys = ON;');
  if (schema !== undefined) db.exec(schema);

  const handle: TestD1 = {
    prepare: (sql: string) => new SqliteStatement(db, sql),
    batch: async (statements: SqliteStatement[]) => {
      db.exec('BEGIN');
      try {
        const results = [];
        for (const statement of statements) results.push(await statement.run());
        db.exec('COMMIT');
        return results;
      } catch (error) {
        db.exec('ROLLBACK');
        throw error;
      }
    },
    withSession: () => handle,
    exec: (sql: string) => db.exec(sql),
    close: () => db.close(),
    raw: db,
  };

  return handle;
}

/** Convenience: an env object good enough for `makeApp().fetch(...)`. */
export function testEnv(
  d1: TestD1,
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    vault1: d1,
    JWT_SECRET: 'test-jwt-secret',
    JWT_REFRESH_SECRET: 'test-refresh-secret',
    ALLOWED_EMAILS: '*@example.com',
    ...overrides,
  };
}
