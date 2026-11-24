import { readFileSync } from 'node:fs';

import { describe, expect, it } from 'vitest';

import {
  HEAVY_DO_ROUTE_METHODS,
  shouldOffloadHeavy,
  shouldOffloadToken,
} from '../../src/routing/heavyRoutes';

/**
 * Parse the Rust-era `HEAVY_DO_ROUTE_METHODS` table out of `src/entry.js` so the
 * TypeScript copy cannot drift while the reference implementation still exists.
 */
function parseReferenceTable(): Map<string, string[]> {
  const source = readFileSync('rust/entry.js', 'utf8');
  const table = new Map<string, string[]>();

  const entryPattern = /\["([^"]+)", new Set\(\[([^\]]*)\]\)\]/g;
  let match = entryPattern.exec(source);
  while (match !== null) {
    const path = match[1] as string;
    const methods = [...(match[2] ?? '').matchAll(/"([A-Z]+)"/g)].map(
      (methodMatch) => methodMatch[1] as string,
    );
    table.set(path, methods.sort());
    match = entryPattern.exec(source);
  }

  return table;
}

describe('HEAVY_DO_ROUTE_METHODS', () => {
  it('matches the Rust reference table exactly', () => {
    const reference = parseReferenceTable();

    // Guard against the regex silently matching nothing.
    expect(reference.size).toBeGreaterThanOrEqual(14);

    expect([...HEAVY_DO_ROUTE_METHODS.keys()].sort()).toEqual([...reference.keys()].sort());

    for (const [path, methods] of reference) {
      const ours = [...(HEAVY_DO_ROUTE_METHODS.get(path) ?? [])].sort();
      expect(ours, `methods for ${path}`).toEqual(methods);
    }
  });
});

describe('shouldOffloadHeavy', () => {
  it('matches methods case-insensitively', () => {
    expect(shouldOffloadHeavy('/api/ciphers/import', 'post')).toBe(true);
    expect(shouldOffloadHeavy('/api/accounts', 'delete')).toBe(true);
  });

  it('rejects unknown paths and methods', () => {
    expect(shouldOffloadHeavy('/api/ciphers/import', 'GET')).toBe(false);
    expect(shouldOffloadHeavy('/api/sync', 'GET')).toBe(false);
  });
});

describe('shouldOffloadToken', () => {
  it('offloads only the plain password grant', () => {
    expect(shouldOffloadToken('password', null)).toBe(true);
  });

  it('keeps auth-request and refresh grants on the main worker', () => {
    expect(shouldOffloadToken('password', 'request-id')).toBe(false);
    expect(shouldOffloadToken('refresh_token', null)).toBe(false);
    expect(shouldOffloadToken(null, null)).toBe(false);
  });
});
