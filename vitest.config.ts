import { defineConfig } from 'vitest/config';

// Unit tests run in plain Node: the crypto helpers rely only on `node:crypto`,
// WebCrypto globals and `btoa`/`atob`, all of which Node provides.
//
// Integration tests (real workerd + D1/KV/R2/DO) will be added as a separate
// project using `@cloudflare/vitest-plugin` once the handlers land.
export default defineConfig({
  test: {
    include: ['tests/unit/**/*.test.ts'],
    environment: 'node',
    reporters: ['default'],
  },
});
