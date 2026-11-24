import { readFileSync } from 'node:fs';

import { beforeEach, describe, expect, it } from 'vitest';

import { makeApp } from '../../src/app';
import type { Env } from '../../src/env';
import { createTestD1, type TestD1, testEnv } from '../helpers/sqlite-d1';

const schema = readFileSync('sql/schema.sql', 'utf8');
const CLIENT_HASH = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=';
const EMAIL = 'user@example.com';

const executionContext = {
  waitUntil: () => undefined,
  passThroughOnException: () => undefined,
} as unknown as ExecutionContext;

const app = makeApp();

let d1: TestD1;
let env: Env;

beforeEach(() => {
  d1 = createTestD1(schema);
  env = testEnv(d1) as unknown as Env;
});

function jsonRequest(path: string, body: unknown, method = 'POST'): Request {
  return new Request(`https://example.com${path}`, {
    method,
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
}

function formRequest(path: string, form: Record<string, string>): Request {
  return new Request(`https://example.com${path}`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams(form).toString(),
  });
}

function registerBody(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    email: EMAIL,
    name: 'User',
    masterPasswordHint: null,
    userAsymmetricKeys: { publicKey: 'pk', encryptedPrivateKey: 'epk' },
    masterPasswordAuthentication: {
      kdf: { kdfType: 0, iterations: 600000 },
      salt: EMAIL,
      hash: CLIENT_HASH,
    },
    masterPasswordUnlock: {
      kdf: { kdfType: 0, iterations: 600000 },
      salt: EMAIL,
      key: 'user-key',
    },
    ...overrides,
  };
}

async function register(overrides: Record<string, unknown> = {}): Promise<Response> {
  return app.fetch(
    jsonRequest('/identity/accounts/register', registerBody(overrides)),
    env,
    executionContext,
  );
}

function loginForm(password = CLIENT_HASH): Record<string, string> {
  return {
    grant_type: 'password',
    username: EMAIL,
    password,
    scope: 'api offline_access',
    client_id: 'cli',
    device_identifier: 'device-1',
    device_name: 'Device',
    device_type: '9',
  };
}

describe('register', () => {
  it('accepts the current 2026.5.0+ format and lowercases the email', async () => {
    // The glob is matched against the RAW email, so only the local part may be
    // uppercase; the stored value must still be lowercased.
    const response = await register({ email: 'User@example.com' });
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({});

    const row = d1.raw
      .prepare('SELECT email, password_iterations, security_stamp FROM users WHERE email = ?1')
      .get(EMAIL) as { email: string; password_iterations: number; security_stamp: string };
    expect(row.email).toBe(EMAIL);
    expect(row.password_iterations).toBe(600000);
    expect(row.security_stamp).toMatch(/^[0-9a-f-]{36}$/);
  });

  it('accepts the legacy format', async () => {
    const response = await app.fetch(
      jsonRequest('/identity/accounts/register', {
        email: EMAIL,
        name: 'User',
        masterPasswordHint: null,
        userAsymmetricKeys: { publicKey: 'pk', encryptedPrivateKey: 'epk' },
        kdf: { kdfType: 0, iterations: 600000 },
        key: 'user-key',
        masterPasswordHash: CLIENT_HASH,
      }),
      env,
      executionContext,
    );
    expect(response.status).toBe(200);
  });

  it('rejects a salt that does not match the email with 422', async () => {
    const response = await register({
      masterPasswordUnlock: {
        kdf: { kdfType: 0, iterations: 600000 },
        salt: 'someone@example.com',
        key: 'user-key',
      },
    });
    expect(response.status).toBe(422);
    expect(await response.json()).toEqual({ error: 'Unexpected RegisterData format' });
  });

  it('enforces ALLOWED_EMAILS', async () => {
    const response = await register({
      email: 'user@nope.test',
      masterPasswordAuthentication: {
        kdf: { kdfType: 0, iterations: 600000 },
        salt: 'user@nope.test',
        hash: CLIENT_HASH,
      },
      masterPasswordUnlock: {
        kdf: { kdfType: 0, iterations: 600000 },
        salt: 'user@nope.test',
        key: 'user-key',
      },
    });
    expect(response.status).toBe(401);
    expect(await response.json()).toEqual({ error: 'Not allowed to signup' });
  });

  it('rejects PBKDF2 below 100000 iterations', async () => {
    const response = await register({
      masterPasswordAuthentication: {
        kdf: { kdfType: 0, iterations: 99999 },
        salt: EMAIL,
        hash: CLIENT_HASH,
      },
      masterPasswordUnlock: {
        kdf: { kdfType: 0, iterations: 99999 },
        salt: EMAIL,
        key: 'user-key',
      },
    });
    expect(response.status).toBe(400);
    expect(await response.json()).toEqual({ error: 'PBKDF2 iterations must be at least 100000' });
  });
});

describe('prelogin', () => {
  it('returns the 600k defaults for an unknown user and null salt', async () => {
    const response = await app.fetch(
      jsonRequest('/identity/accounts/prelogin', { email: 'nobody@example.com' }),
      env,
      executionContext,
    );
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({
      kdf: 0,
      kdfIterations: 600000,
      kdfMemory: null,
      kdfParallelism: null,
      kdfSettings: { iterations: 600000, kdfType: 0, memory: null, parallelism: null },
      salt: null,
    });
  });

  it('does not lowercase the email before lookup', async () => {
    await register({
      masterPasswordAuthentication: {
        kdf: { kdfType: 0, iterations: 200000 },
        salt: EMAIL,
        hash: CLIENT_HASH,
      },
      masterPasswordUnlock: {
        kdf: { kdfType: 0, iterations: 200000 },
        salt: EMAIL,
        key: 'user-key',
      },
    });

    const lower = await app.fetch(
      jsonRequest('/identity/accounts/prelogin', { email: EMAIL }),
      env,
      executionContext,
    );
    expect(((await lower.json()) as { kdfIterations: number }).kdfIterations).toBe(200000);

    const mixed = await app.fetch(
      jsonRequest('/identity/accounts/prelogin', { email: 'User@Example.com' }),
      env,
      executionContext,
    );
    expect(((await mixed.json()) as { kdfIterations: number }).kdfIterations).toBe(600000);
  });
});

describe('password grant', () => {
  it('rejects a wrong password with 401', async () => {
    await register();
    const response = await app.fetch(
      formRequest('/identity/connect/token', loginForm('wrong')),
      env,
      executionContext,
    );
    expect(response.status).toBe(401);
    expect(await response.json()).toEqual({ error: 'Invalid credentials' });
  });

  it('rejects an unknown user with the same message', async () => {
    const fastEnv = { ...env, LOGIN_MISSING_USER_DELAY_MS: '0' } as unknown as Env;
    const response = await app.fetch(
      formRequest('/identity/connect/token', loginForm()),
      fastEnv,
      executionContext,
    );
    expect(response.status).toBe(401);
    expect(await response.json()).toEqual({ error: 'Invalid credentials' });
  });

  it('issues tokens and creates the device row', async () => {
    await register();
    const response = await app.fetch(
      formRequest('/identity/connect/token', loginForm()),
      env,
      executionContext,
    );
    expect(response.status).toBe(200);

    const body = (await response.json()) as Record<string, unknown>;
    expect(body.token_type).toBe('Bearer');
    expect(body.expires_in).toBe(3600);
    expect(body.scope).toBe('api offline_access');
    expect(typeof body.access_token).toBe('string');
    expect(typeof body.refresh_token).toBe('string');
    expect(body.Key).toBe('user-key');
    expect(body.Kdf).toBe(0);
    expect(body.UserDecryptionOptions).toMatchObject({
      HasMasterPassword: true,
      Object: 'userDecryptionOptions',
    });
    expect('TwoFactorToken' in body).toBe(false);

    const device = d1.raw
      .prepare('SELECT identifier, type, refresh_token FROM devices WHERE identifier = ?1')
      .get('device-1') as { identifier: string; type: number; refresh_token: string };
    expect(device.type).toBe(9);
    expect(device.refresh_token).toHaveLength(88);
  });

  it('refreshes tokens without rotating the device token', async () => {
    await register();
    const first = (await (
      await app.fetch(formRequest('/identity/connect/token', loginForm()), env, executionContext)
    ).json()) as Record<string, string>;

    const response = await app.fetch(
      formRequest('/identity/connect/token', {
        grant_type: 'refresh_token',
        refresh_token: first.refresh_token as string,
        client_id: 'cli',
      }),
      env,
      executionContext,
    );
    expect(response.status).toBe(200);

    const body = (await response.json()) as Record<string, string>;
    expect(typeof body.access_token).toBe('string');
    expect(body.Key).toBe('user-key');
    expect(body.expires_in).toBe(3600);
    // The opaque device token is stable, so the device row is not rotated.
    const device = d1.raw
      .prepare('SELECT refresh_token FROM devices WHERE identifier = ?1')
      .get('device-1') as { refresh_token: string };
    expect(device.refresh_token).toHaveLength(88);
  });

  it('rejects an unknown grant type with invalid_grant', async () => {
    const response = await app.fetch(
      formRequest('/identity/connect/token', { grant_type: 'client_credentials' }),
      env,
      executionContext,
    );
    expect(response.status).toBe(400);
    expect(await response.json()).toEqual({ error: 'invalid_grant' });
  });
});
