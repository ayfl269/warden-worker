/**
 * Local HTTP server for contract replay: runs the real Hono app on Node with a
 * SQLite-backed D1 adapter. Not for production use.
 *
 *   node tools/serve-ts.mjs [port]
 */
import { readFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { DatabaseSync } from 'node:sqlite';

import { makeApp } from '../src/app.ts';

const PORT = Number(process.argv[2] ?? 8788);
const db = new DatabaseSync(':memory:');
db.exec('PRAGMA foreign_keys = ON;');
db.exec(readFileSync('sql/schema.sql', 'utf8'));

class Statement {
  constructor(sql, params = []) {
    this.sql = sql;
    this.params = params;
  }
  bind(...values) {
    return new Statement(this.sql, values.map((v) => (v === undefined ? null : v)));
  }
  async first() {
    return db.prepare(this.sql).get(...this.params) ?? null;
  }
  async all() {
    return { results: db.prepare(this.sql).all(...this.params) };
  }
  async run() {
    db.prepare(this.sql).run(...this.params);
    return { success: true };
  }
}

const d1 = {
  prepare: (sql) => new Statement(sql),
  batch: async (statements) => {
    db.exec('BEGIN');
    try {
      for (const statement of statements) await statement.run();
      db.exec('COMMIT');
    } catch (error) {
      db.exec('ROLLBACK');
      throw error;
    }
    return [];
  },
  withSession: () => d1,
  exec: (sql) => db.exec(sql),
};

const env = {
  vault1: d1,
  JWT_SECRET: 'local-jwt-secret',
  JWT_REFRESH_SECRET: 'local-refresh-secret',
  ALLOWED_EMAILS: '*@ayfl.cn',
};

const app = makeApp();

const server = createServer((req, res) => {
  const chunks = [];
  req.on('data', (chunk) => chunks.push(chunk));
  req.on('end', async () => {
    const body = chunks.length > 0 ? Buffer.concat(chunks) : undefined;
    const url = `http://127.0.0.1:${PORT}${req.url}`;
    const headers = new Headers();
    for (const [key, value] of Object.entries(req.headers)) {
      if (typeof value === 'string') headers.set(key, value);
      else if (Array.isArray(value)) headers.set(key, value.join(', '));
    }

    const request = new Request(url, {
      method: req.method,
      headers,
      body: req.method === 'GET' || req.method === 'HEAD' ? undefined : body,
    });

    try {
      const response = await app.fetch(request, env, {
        waitUntil: () => {},
        passThroughOnException: () => {},
      });
      const buffer = Buffer.from(await response.arrayBuffer());
      res.writeHead(response.status, Object.fromEntries(response.headers));
      res.end(buffer);
    } catch (error) {
      res.writeHead(500, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ error: String(error) }));
    }
  });
});

server.listen(PORT, '127.0.0.1', () => {
  console.log(`TS worker listening on http://127.0.0.1:${PORT}`);
});
