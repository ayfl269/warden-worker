import { describe, expect, it } from 'vitest';

import { makeApp } from '../../src/app';
import type { Env } from '../../src/env';

const executionContext = {
  waitUntil: () => undefined,
  passThroughOnException: () => undefined,
} as unknown as ExecutionContext;

const emptyEnv = {} as Env;

interface ConfigBody {
  version: string;
  gitHash: string;
  object: string;
  server: { name: string };
  settings: { disableUserRegistration: boolean };
  environment: Record<string, string | null>;
  push: { pushTechnology: number; vapidPublicKey: string | null };
}

function request(path: string, init?: RequestInit): Request {
  return new Request(`https://vault.example.com${path}`, init);
}

describe('app routing', () => {
  const app = makeApp();

  it('serves /api/config with the emulated version and derived URLs', async () => {
    const response = await app.fetch(request('/api/config'), emptyEnv, executionContext);
    expect(response.status).toBe(200);

    const body = (await response.json()) as ConfigBody;
    expect(body.version).toBe('2026.6.0');
    expect(body.gitHash).toBe('5d84f176');
    expect(body.object).toBe('config');
    expect(body.server.name).toBe('Vaultwarden');
    expect(body.environment).toEqual({
      vault: 'https://vault.example.com',
      api: 'https://vault.example.com/api',
      identity: 'https://vault.example.com/identity',
      notifications: 'https://vault.example.com/notifications',
      sso: '',
      cloudRegion: null,
    });
    expect(body.settings.disableUserRegistration).toBe(true);
    expect(body.push).toEqual({ pushTechnology: 0, vapidPublicKey: null });
  });

  it('prefers BASE_URL over the request origin', async () => {
    const env = { BASE_URL: 'https://custom.example.com/' } as Env;
    const response = await app.fetch(request('/api/config'), env, executionContext);
    const body = (await response.json()) as ConfigBody;
    expect(body.environment.vault).toBe('https://custom.example.com');
  });

  it('serves the meta endpoints', async () => {
    const version = await app.fetch(request('/api/version'), emptyEnv, executionContext);
    expect(version.status).toBe(200);
    expect(await version.text()).toBe('"2026.6.0"');

    const now = await app.fetch(request('/api/now'), emptyEnv, executionContext);
    const nowValue = (await now.json()) as string;
    expect(nowValue).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/);

    const hibp = await app.fetch(request('/api/hibp/breach'), emptyEnv, executionContext);
    expect(await hibp.text()).toBe('[]');
  });

  it('returns an empty 404 body for unknown paths', async () => {
    const response = await app.fetch(request('/api/does-not-exist'), emptyEnv, executionContext);
    expect(response.status).toBe(404);
    expect(await response.text()).toBe('');
  });

  it('returns 405 with Allow when the path exists with another method', async () => {
    const response = await app.fetch(
      request('/api/config', { method: 'POST' }),
      emptyEnv,
      executionContext,
    );
    expect(response.status).toBe(405);
    expect(response.headers.get('allow')).toBe('GET');
    expect(await response.text()).toBe('');
  });

  it('answers CORS preflight like tower-http', async () => {
    const response = await app.fetch(
      request('/api/config', { method: 'OPTIONS' }),
      emptyEnv,
      executionContext,
    );
    expect(response.status).toBe(200);
    expect(response.headers.get('access-control-allow-origin')).toBe('*');
    expect(response.headers.get('access-control-allow-methods')).toBe('*');
    expect(response.headers.get('access-control-allow-headers')).toBe('*');
  });

  it('adds the CORS origin header to normal responses', async () => {
    const response = await app.fetch(request('/api/version'), emptyEnv, executionContext);
    expect(response.headers.get('access-control-allow-origin')).toBe('*');
  });
});
