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

  const body = (await response.json()) as { access_token: string };
  return body.access_token;
}

beforeEach(async () => {
  d1 = createTestD1(schema);
  env = testEnv(d1) as unknown as Env;
  token = await registerAndLogin();
});

// Regression: the Web Vault sends the SDK property names
// (`masterPasswordAuthenticationHash` / `masterKeyWrappedUserKey`), while the
// reference implementation accepts both spellings through serde aliases. The
// port only accepted `hash` / `key`, so every registration from the browser
// failed with "expected string, received undefined".
describe('registration payload compatibility', () => {
  const kdf = { kdfType: 0, iterations: 600000 };

  function base(email: string): Record<string, unknown> {
    return {
      email,
      name: 'User',
      masterPasswordHint: null,
      userAsymmetricKeys: { publicKey: 'pk', encryptedPrivateKey: 'epk' },
    };
  }

  it('accepts the SDK field names sent by current clients', async () => {
    const email = 'sdk@example.com';
    const response = await app.fetch(
      jsonRequest('/identity/accounts/register', {
        ...base(email),
        masterPasswordAuthentication: {
          kdf,
          salt: email,
          masterPasswordAuthenticationHash: CLIENT_HASH,
        },
        masterPasswordUnlock: {
          kdf,
          salt: email,
          masterKeyWrappedUserKey: 'wrapped-user-key',
        },
      }),
      env,
      executionContext,
    );
    expect(response.status).toBe(200);

    const row = d1.raw
      .prepare('SELECT key, kdf_iterations FROM users WHERE email = ?')
      .get(email) as {
      key: string;
      kdf_iterations: number;
    };
    expect(row.key).toBe('wrapped-user-key');
    expect(row.kdf_iterations).toBe(600000);
  });

  it('still accepts the short hash/key spelling', async () => {
    const email = 'short@example.com';
    const response = await app.fetch(
      jsonRequest('/identity/accounts/register', {
        ...base(email),
        masterPasswordAuthentication: { kdf, salt: email, hash: CLIENT_HASH },
        masterPasswordUnlock: { kdf, salt: email, key: 'wrapped-user-key' },
      }),
      env,
      executionContext,
    );
    expect(response.status).toBe(200);
  });

  it('rejects a payload with neither spelling', async () => {
    const email = 'empty@example.com';
    const response = await app.fetch(
      jsonRequest('/identity/accounts/register', {
        ...base(email),
        masterPasswordAuthentication: { kdf, salt: email },
        masterPasswordUnlock: { kdf, salt: email },
      }),
      env,
      executionContext,
    );
    expect(response.status).toBe(422);
  });
});

describe('profile', () => {
  it('returns the profile with a microsecond creationDate', async () => {
    const response = await app.fetch(
      getRequest('/api/accounts/profile', token),
      env,
      executionContext,
    );
    expect(response.status).toBe(200);

    const body = (await response.json()) as Record<string, unknown>;
    expect(body.object).toBe('profile');
    expect(body.email).toBe(EMAIL);
    expect(body.name).toBe('User');
    expect(body.emailVerified).toBe(true);
    expect(body.premium).toBe(true);
    expect(body._status).toBe(0);
    expect(body.creationDate).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$/);
    expect(body.accountKeys).toMatchObject({
      object: 'privateKeys',
      securityState: null,
      signatureKeyPair: null,
    });
  });

  it('rejects a name longer than 50 characters', async () => {
    const response = await app.fetch(
      jsonRequest('/api/accounts/profile', { name: 'x'.repeat(51) }, 'POST', token),
      env,
      executionContext,
    );
    expect(response.status).toBe(400);
    expect(await response.json()).toEqual({
      error: 'The field Name must be a string with a maximum length of 50.',
    });
  });

  it('updates the display name', async () => {
    const response = await app.fetch(
      jsonRequest('/api/accounts/profile', { name: 'Renamed' }, 'POST', token),
      env,
      executionContext,
    );
    expect(response.status).toBe(200);
    expect(((await response.json()) as { name: string }).name).toBe('Renamed');
  });

  it('validates the avatar colour length', async () => {
    const bad = await app.fetch(
      jsonRequest('/api/accounts/avatar', { avatarColor: '#fff' }, 'PUT', token),
      env,
      executionContext,
    );
    expect(bad.status).toBe(400);

    const good = await app.fetch(
      jsonRequest('/api/accounts/avatar', { avatarColor: '#123456' }, 'PUT', token),
      env,
      executionContext,
    );
    expect(good.status).toBe(200);
    expect(((await good.json()) as { avatarColor: string }).avatarColor).toBe('#123456');
  });

  it('returns a millisecond revision date', async () => {
    const response = await app.fetch(
      getRequest('/api/accounts/revision-date', token),
      env,
      executionContext,
    );
    expect(response.status).toBe(200);
    const value = (await response.json()) as number;
    expect(typeof value).toBe('number');
    expect(value).toBeGreaterThan(0);
  });

  it('requires authentication', async () => {
    const response = await app.fetch(
      new Request('https://example.com/api/accounts/profile'),
      env,
      executionContext,
    );
    expect(response.status).toBe(401);
    expect(await response.json()).toEqual({ error: 'Missing or invalid token' });
  });
});

describe('session invalidation', () => {
  it('rotates the security stamp on password change and rejects the old token', async () => {
    const before = d1.raw.prepare('SELECT security_stamp FROM users').get() as {
      security_stamp: string;
    };

    const response = await app.fetch(
      jsonRequest(
        '/api/accounts/password',
        {
          masterPasswordHash: CLIENT_HASH,
          newMasterPasswordHash: CLIENT_HASH,
          masterPasswordHint: null,
          key: 'new-user-key',
        },
        'POST',
        token,
      ),
      env,
      executionContext,
    );
    expect(response.status).toBe(200);

    const after = d1.raw.prepare('SELECT security_stamp FROM users').get() as {
      security_stamp: string;
    };
    expect(after.security_stamp).not.toBe(before.security_stamp);

    const stale = await app.fetch(
      getRequest('/api/accounts/profile', token),
      env,
      executionContext,
    );
    expect(stale.status).toBe(401);
    expect(await stale.json()).toEqual({ error: 'Invalid token' });
  });

  it('rejects a wrong current password', async () => {
    const response = await app.fetch(
      jsonRequest(
        '/api/accounts/password',
        {
          masterPasswordHash: 'wrong',
          newMasterPasswordHash: CLIENT_HASH,
          masterPasswordHint: null,
          key: 'k',
        },
        'POST',
        token,
      ),
      env,
      executionContext,
    );
    expect(response.status).toBe(401);
    expect(await response.json()).toEqual({ error: 'Invalid password' });
  });

  it('deletes all devices on security-stamp rotation', async () => {
    const response = await app.fetch(
      jsonRequest(
        '/api/accounts/security-stamp',
        { masterPasswordHash: CLIENT_HASH },
        'POST',
        token,
      ),
      env,
      executionContext,
    );
    expect(response.status).toBe(200);

    const devices = d1.raw.prepare('SELECT COUNT(*) AS c FROM devices').get() as { c: number };
    expect(devices.c).toBe(0);

    const stale = await app.fetch(
      getRequest('/api/accounts/profile', token),
      env,
      executionContext,
    );
    expect(stale.status).toBe(401);
  });
});

describe('account deletion', () => {
  it('requires the master password hash', async () => {
    const response = await app.fetch(
      jsonRequest('/api/accounts', {}, 'DELETE', token),
      env,
      executionContext,
    );
    expect(response.status).toBe(400);
    expect(await response.json()).toEqual({ error: 'Missing master password hash' });
  });

  it('deletes the user and their rows', async () => {
    const response = await app.fetch(
      jsonRequest('/api/accounts', { masterPasswordHash: CLIENT_HASH }, 'DELETE', token),
      env,
      executionContext,
    );
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({});

    const users = d1.raw.prepare('SELECT COUNT(*) AS c FROM users').get() as { c: number };
    expect(users.c).toBe(0);
    const devices = d1.raw.prepare('SELECT COUNT(*) AS c FROM devices').get() as { c: number };
    expect(devices.c).toBe(0);
  });
});
