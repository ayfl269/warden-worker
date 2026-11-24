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
let token: string;

function jsonRequest(path: string, body: unknown, method = 'POST', bearer?: string): Request {
  const headers: Record<string, string> = { 'content-type': 'application/json' };
  if (bearer !== undefined) headers.authorization = `Bearer ${bearer}`;
  return new Request(`https://example.com${path}`, {
    method,
    headers,
    body: JSON.stringify(body),
  });
}

function getRequest(path: string, bearer: string): Request {
  return new Request(`https://example.com${path}`, {
    headers: { authorization: `Bearer ${bearer}` },
  });
}

async function registerAndLogin(): Promise<string> {
  const kdf = { kdfType: 0, iterations: 600000 };
  await app.fetch(
    jsonRequest('/identity/accounts/register', {
      email: EMAIL,
      name: 'User',
      masterPasswordHint: null,
      userAsymmetricKeys: { publicKey: 'pk', encryptedPrivateKey: 'epk' },
      masterPasswordAuthentication: { kdf, salt: EMAIL, hash: CLIENT_HASH },
      masterPasswordUnlock: { kdf, salt: EMAIL, key: 'user-key' },
    }),
    env,
    executionContext,
  );

  const response = await app.fetch(
    new Request('https://example.com/identity/connect/token', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'password',
        username: EMAIL,
        password: CLIENT_HASH,
        scope: 'api offline_access',
        client_id: 'cli',
        device_identifier: 'device-1',
        device_name: 'Device',
        device_type: '9',
      }).toString(),
    }),
    env,
    executionContext,
  );
  return ((await response.json()) as { access_token: string }).access_token;
}

function kdfBody(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  const kdf = { kdfType: 0, iterations: 200000 };
  return {
    masterPasswordHash: CLIENT_HASH,
    authenticationData: {
      salt: EMAIL,
      kdf,
      masterPasswordAuthenticationHash: CLIENT_HASH,
    },
    unlockData: {
      salt: EMAIL,
      kdf,
      masterKeyWrappedUserKey: 'new-key',
    },
    ...overrides,
  };
}

beforeEach(async () => {
  d1 = createTestD1(schema);
  env = testEnv(d1) as unknown as Env;
  token = await registerAndLogin();
});

describe('change KDF', () => {
  it('updates the KDF parameters, rotates the stamp and invalidates old tokens', async () => {
    const response = await app.fetch(
      jsonRequest('/api/accounts/kdf', kdfBody(), 'POST', token),
      env,
      executionContext,
    );
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({});

    const row = d1.raw
      .prepare(
        'SELECT kdf_type, kdf_iterations, kdf_memory, kdf_parallelism, key, password_iterations, security_stamp FROM users',
      )
      .get() as {
      kdf_type: number;
      kdf_iterations: number;
      kdf_memory: number | null;
      kdf_parallelism: number | null;
      key: string;
      password_iterations: number;
      security_stamp: string;
    };
    expect(row.kdf_type).toBe(0);
    expect(row.kdf_iterations).toBe(200000);
    expect(row.kdf_memory).toBeNull();
    expect(row.kdf_parallelism).toBeNull();
    expect(row.key).toBe('new-key');
    expect(row.password_iterations).toBe(600000);

    const stale = await app.fetch(
      getRequest('/api/accounts/profile', token),
      env,
      executionContext,
    );
    expect(stale.status).toBe(401);
  });

  it('accepts the kdf/iterations aliases', async () => {
    const response = await app.fetch(
      jsonRequest(
        '/api/accounts/kdf',
        kdfBody({
          authenticationData: {
            salt: EMAIL,
            kdf: { kdf: 0, iterations: 150000 },
            masterPasswordAuthenticationHash: CLIENT_HASH,
          },
          unlockData: {
            salt: EMAIL,
            kdf: { kdf: 0, iterations: 150000 },
            masterKeyWrappedUserKey: 'k',
          },
        }),
        'POST',
        token,
      ),
      env,
      executionContext,
    );
    expect(response.status).toBe(200);

    const row = d1.raw.prepare('SELECT kdf_iterations FROM users').get() as {
      kdf_iterations: number;
    };
    expect(row.kdf_iterations).toBe(150000);
  });

  it('rejects mismatched authentication and unlock KDFs', async () => {
    const response = await app.fetch(
      jsonRequest(
        '/api/accounts/kdf',
        kdfBody({
          unlockData: {
            salt: EMAIL,
            kdf: { kdfType: 0, iterations: 300000 },
            masterKeyWrappedUserKey: 'k',
          },
        }),
        'POST',
        token,
      ),
      env,
      executionContext,
    );
    expect(response.status).toBe(400);
    expect(await response.json()).toEqual({
      error: 'KDF settings must be equal for authentication and unlock',
    });
  });

  it('rejects a salt that is not the account email', async () => {
    const response = await app.fetch(
      jsonRequest(
        '/api/accounts/kdf',
        kdfBody({
          authenticationData: {
            salt: 'other@example.com',
            kdf: { kdfType: 0, iterations: 200000 },
            masterPasswordAuthenticationHash: CLIENT_HASH,
          },
        }),
        'POST',
        token,
      ),
      env,
      executionContext,
    );
    expect(response.status).toBe(400);
    expect(await response.json()).toEqual({ error: 'Invalid master password salt' });
  });

  it('rejects an unsupported KDF type', async () => {
    const response = await app.fetch(
      jsonRequest(
        '/api/accounts/kdf',
        kdfBody({
          authenticationData: {
            salt: EMAIL,
            kdf: { kdfType: 2, iterations: 200000 },
            masterPasswordAuthenticationHash: CLIENT_HASH,
          },
          unlockData: {
            salt: EMAIL,
            kdf: { kdfType: 2, iterations: 200000 },
            masterKeyWrappedUserKey: 'k',
          },
        }),
        'POST',
        token,
      ),
      env,
      executionContext,
    );
    expect(response.status).toBe(400);
    expect(await response.json()).toEqual({
      error: 'Unsupported KDF type. Only PBKDF2 (0) and Argon2id (1) are supported',
    });
  });

  it('rejects a wrong master password', async () => {
    const response = await app.fetch(
      jsonRequest('/api/accounts/kdf', kdfBody({ masterPasswordHash: 'nope' }), 'POST', token),
      env,
      executionContext,
    );
    expect(response.status).toBe(401);
    expect(await response.json()).toEqual({ error: 'Invalid password' });
  });
});
