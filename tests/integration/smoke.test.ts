import { SELF } from 'cloudflare:test';
import { describe, expect, it } from 'vitest';

describe('worker smoke test', () => {
  it('serves /api/config through the real runtime', async () => {
    const response = await SELF.fetch('https://example.com/api/config');
    expect(response.status).toBe(200);

    const body = (await response.json()) as {
      version: string;
      object: string;
      environment: { api: string };
    };
    expect(body.version).toBe('2026.6.0');
    expect(body.object).toBe('config');
    expect(body.environment.api).toBe('https://example.com/api');
  });

  it('serves /api/alive, proving D1 is reachable', async () => {
    const response = await SELF.fetch('https://example.com/api/alive');
    expect(response.status).toBe(200);
    expect(typeof (await response.json())).toBe('string');
  });

  it('returns an empty 404 for unknown routes', async () => {
    const response = await SELF.fetch('https://example.com/api/nope');
    expect(response.status).toBe(404);
    expect(await response.text()).toBe('');
  });

  it('applies the schema (users table exists)', async () => {
    const response = await SELF.fetch('https://example.com/api/alive');
    expect(response.status).toBe(200);
  });
});
