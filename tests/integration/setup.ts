import { env } from 'cloudflare:test';
import { beforeAll } from 'vitest';

import type { Env } from '../../src/env';

// The plugin types `env` from the Worker's bindings, but the extra `TEST_SCHEMA`
// binding is only declared here, so narrow once instead of augmenting the module.
const testEnv = env as unknown as Env & { TEST_SCHEMA: string };

// Each test file gets isolated storage, so the schema is created once per file.
beforeAll(async () => {
  await testEnv.vault1.exec(testEnv.TEST_SCHEMA);
});
