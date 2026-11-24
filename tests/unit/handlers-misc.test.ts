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
  return new Request(`https://example.com${path}`, { method, headers, body: JSON.stringify(body) });
}

function getRequest(path: string, bearer?: string): Request {
  const headers: Record<string, string> = {};
  if (bearer !== undefined) headers.authorization = `Bearer ${bearer}`;
  return new Request(`https://example.com${path}`, { headers });
}

async function registerAndLogin(): Promise<string> {
  const kdf = { kdfType: 0, iterations: 600000 };
  await app.fetch(
    jsonRequest('/identity/accounts/register', {
      email: EMAIL,
      name: 'User',
      masterPasswordHint: 'my hint',
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

beforeEach(async () => {
  d1 = createTestD1(schema);
  env = testEnv(d1) as unknown as Env;
  token = await registerAndLogin();
});

describe('password hint', () => {
  it('returns the stored hint in the error message', async () => {
    const response = await app.fetch(
      jsonRequest('/api/accounts/password-hint', { email: EMAIL }),
      env,
      executionContext,
    );
    expect(response.status).toBe(400);
    expect(await response.json()).toEqual({ error: 'Your password hint is: my hint' });
  });

  it('returns the generic message for unknown emails', async () => {
    const response = await app.fetch(
      jsonRequest('/api/accounts/password-hint', { email: 'nobody@example.com' }),
      env,
      executionContext,
    );
    expect(response.status).toBe(400);
    expect(await response.json()).toEqual({ error: 'Sorry, you have no password hint...' });
  });
});

describe('compatibility stubs', () => {
  it('returns a fixed verification token', async () => {
    const response = await app.fetch(
      new Request('https://example.com/identity/accounts/register/send-verification-email', {
        method: 'POST',
      }),
      env,
      executionContext,
    );
    expect(response.status).toBe(200);
    expect(await response.json()).toBe('fixed-token-to-mock');
  });

  it('returns empty emergency-access lists', async () => {
    for (const path of ['/api/emergency-access/trusted', '/api/emergency-access/granted']) {
      const response = await app.fetch(getRequest(path, token), env, executionContext);
      expect(response.status).toBe(200);
      expect(await response.json()).toEqual({
        data: [],
        object: 'list',
        continuationToken: null,
      });
    }
  });

  it('returns an empty webauthn list', async () => {
    const response = await app.fetch(getRequest('/api/webauthn', token), env, executionContext);
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({
      object: 'list',
      data: [],
      continuationToken: null,
    });
  });

  it('requires authentication for the stubs', async () => {
    const response = await app.fetch(
      getRequest('/api/emergency-access/trusted'),
      env,
      executionContext,
    );
    expect(response.status).toBe(401);
  });
});
