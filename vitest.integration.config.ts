import { readFileSync } from 'node:fs';

import { cloudflareTest } from '@cloudflare/vitest-plugin';
import { defineConfig } from 'vitest/config';

// The final schema (sql/schema.sql) is applied to a fresh local D1 before each
// test file, so integration tests exercise real SQLite/D1 semantics.
const schema = readFileSync('sql/schema.sql', 'utf8');

export default defineConfig({
  plugins: [
    cloudflareTest({
      wrangler: { configPath: './wrangler.ts.toml' },
      miniflare: {
        bindings: {
          JWT_SECRET: 'integration-jwt-secret',
          JWT_REFRESH_SECRET: 'integration-refresh-secret',
          ALLOWED_EMAILS: '*@example.com',
          TEST_SCHEMA: schema,
        },
      },
    }),
  ],
  test: {
    include: ['tests/integration/**/*.test.ts'],
    setupFiles: ['./tests/integration/setup.ts'],
  },
});
