import { readFileSync } from 'node:fs';

import { describe, expect, it } from 'vitest';

import { makeApp } from '../../src/app';

/**
 * Route-table parity check against the Rust reference implementation.
 *
 * Both sides are normalized to `"METHOD /path/{param}"` so that Rust's `{id}`
 * and Hono's `:id` compare equal. This test is tied to `src/router.rs` and must
 * be replaced with a frozen snapshot when the Rust sources are removed.
 */

function normalizePath(path: string): string {
  return path
    .replace(/\{[^}]+\}/g, '{}')
    .replace(/:[A-Za-z0-9_]+/g, '{}')
    .replace(/\/+$/, '');
}

function parseRustRoutes(): string[] {
  const source = readFileSync('rust/router.rs', 'utf8');
  const routes: string[] = [];

  // Splitting on `.route(` means each segment contains exactly one declaration,
  // including chained handlers such as `get(a).post(b)`.
  const segments = source.split('.route(');
  for (const segment of segments.slice(1)) {
    const pathMatch = /^\s*"([^"]+)"/.exec(segment);
    if (pathMatch === null) continue;

    const path = normalizePath(pathMatch[1] as string);
    const methods = [...segment.matchAll(/\b(get|post|put|delete)\(/g)].map((match) =>
      (match[1] as string).toUpperCase(),
    );

    for (const method of methods) {
      routes.push(`${method} ${path}`);
    }
  }

  return [...new Set(routes)].sort();
}

function parseTsRoutes(): string[] {
  const app = makeApp();
  const routes = app.routes
    .filter((route) => route.method !== 'ALL')
    .map((route) => `${route.method} ${normalizePath(route.path)}`);

  return [...new Set(routes)].sort();
}

describe('route table parity', () => {
  it('matches src/router.rs', () => {
    const rust = parseRustRoutes();
    const ts = parseTsRoutes();

    // Sanity check: the Rust parser found a substantial number of routes.
    expect(rust.length).toBeGreaterThan(50);

    expect(ts).toEqual(rust);
  });
});
