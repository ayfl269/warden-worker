import { readFileSync } from 'node:fs';

import { beforeEach, describe, expect, it } from 'vitest';
import { makeApp } from '../../src/app';
import { bytesToBase64UrlNoPad } from '../../src/auth/base64';
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

function getRequest(path: string, bearer: string, extra: Record<string, string> = {}): Request {
  return new Request(`https://example.com${path}`, {
    headers: { authorization: `Bearer ${bearer}`, ...extra },
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

beforeEach(async () => {
  d1 = createTestD1(schema);
  env = testEnv(d1) as unknown as Env;
  token = await registerAndLogin();
});

describe('device listing', () => {
  it('lists the current device with a null pending auth request', async () => {
    const response = await app.fetch(getRequest('/api/devices', token), env, executionContext);
    expect(response.status).toBe(200);

    const body = (await response.json()) as {
      data: Array<Record<string, unknown>>;
      object: string;
      continuationToken: null;
    };
    expect(body.object).toBe('list');
    expect(body.continuationToken).toBeNull();
    expect(body.data).toHaveLength(1);
    expect(body.data[0]).toMatchObject({
      id: 'device-1',
      identifier: 'device-1',
      name: 'Device',
      type: 9,
      isTrusted: false,
      encryptedPublicKey: null,
      encryptedUserKey: null,
      object: 'device',
      devicePendingAuthRequest: null,
    });
  });
});

describe('knowndevice', () => {
  it('returns true for a known device and false otherwise', async () => {
    const email = bytesToBase64UrlNoPad(new TextEncoder().encode(EMAIL));

    const known = await app.fetch(
      new Request('https://example.com/api/devices/knowndevice', {
        headers: { 'X-Request-Email': email, 'X-Device-Identifier': 'device-1' },
      }),
      env,
      executionContext,
    );
    expect(await known.json()).toBe(true);

    const unknown = await app.fetch(
      new Request('https://example.com/api/devices/knowndevice', {
        headers: { 'X-Request-Email': email, 'X-Device-Identifier': 'other' },
      }),
      env,
      executionContext,
    );
    expect(await unknown.json()).toBe(false);
  });

  it('requires both headers', async () => {
    const response = await app.fetch(
      new Request('https://example.com/api/devices/knowndevice'),
      env,
      executionContext,
    );
    expect(response.status).toBe(400);
    expect(await response.json()).toEqual({ error: 'Missing X-Request-Email header' });
  });

  it('rejects an invalid base64 email', async () => {
    const response = await app.fetch(
      new Request('https://example.com/api/devices/knowndevice', {
        headers: { 'X-Request-Email': '!!!', 'X-Device-Identifier': 'device-1' },
      }),
      env,
      executionContext,
    );
    expect(response.status).toBe(400);
    expect(await response.json()).toEqual({ error: 'Invalid X-Request-Email header' });
  });
});

describe('device lookup', () => {
  it('returns the device by identifier', async () => {
    const response = await app.fetch(
      getRequest('/api/devices/identifier/device-1', token),
      env,
      executionContext,
    );
    expect(response.status).toBe(200);
    expect(((await response.json()) as { object: string }).object).toBe('device');
  });

  it('returns 404 for an unknown identifier', async () => {
    const response = await app.fetch(
      getRequest('/api/devices/identifier/other', token),
      env,
      executionContext,
    );
    expect(response.status).toBe(404);
    expect(await response.json()).toEqual({ error: 'Device not found' });
  });
});

describe('device revocation', () => {
  it('deletes the device and invalidates its session', async () => {
    const revoked = await app.fetch(
      new Request('https://example.com/api/devices/device-1', {
        method: 'DELETE',
        headers: { authorization: `Bearer ${token}` },
      }),
      env,
      executionContext,
    );
    expect(revoked.status).toBe(200);

    // The auth middleware requires the device row to still exist.
    const after = await app.fetch(
      getRequest('/api/accounts/profile', token),
      env,
      executionContext,
    );
    expect(after.status).toBe(401);
  });

  it('returns 404 for a device owned by somebody else', async () => {
    const response = await app.fetch(
      new Request('https://example.com/api/devices/not-mine', {
        method: 'DELETE',
        headers: { authorization: `Bearer ${token}` },
      }),
      env,
      executionContext,
    );
    expect(response.status).toBe(404);
    expect(await response.json()).toEqual({ error: 'Device not found' });
  });
});

describe('push token management', () => {
  it('stores a push token', async () => {
    const response = await app.fetch(
      jsonRequest(
        '/api/devices/identifier/device-1/token',
        { pushToken: ' push-token ' },
        'POST',
        token,
      ),
      env,
      executionContext,
    );
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({});

    const row = d1.raw
      .prepare('SELECT push_token FROM devices WHERE identifier = ?1')
      .get('device-1') as { push_token: string };
    expect(row.push_token).toBe('push-token');
  });

  it('rejects an empty token', async () => {
    const response = await app.fetch(
      jsonRequest('/api/devices/identifier/device-1/token', { pushToken: '   ' }, 'POST', token),
      env,
      executionContext,
    );
    expect(response.status).toBe(400);
    expect(await response.json()).toEqual({ error: 'Missing pushToken' });
  });

  it('refuses to manage another device', async () => {
    const response = await app.fetch(
      jsonRequest('/api/devices/identifier/other/token', { pushToken: 't' }, 'POST', token),
      env,
      executionContext,
    );
    expect(response.status).toBe(401);
    expect(await response.json()).toEqual({
      error: 'Can only manage the current authenticated device',
    });
  });

  it('registers with the push relay when push is enabled', async () => {
    const calls: string[] = [];
    const originalFetch = globalThis.fetch;
    globalThis.fetch = (async (input: RequestInfo | URL) => {
      calls.push(String(input));
      return new Response(JSON.stringify({ access_token: 'relay', expires_in: 3600 }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    }) as typeof fetch;

    try {
      env = {
        ...env,
        PUSH_ENABLED: 'true',
        PUSH_INSTALLATION_ID: 'install',
        PUSH_INSTALLATION_KEY: 'key',
      } as unknown as Env;

      const response = await app.fetch(
        jsonRequest(
          '/api/devices/identifier/device-1/token',
          { pushToken: 'push-token' },
          'POST',
          token,
        ),
        env,
        executionContext,
      );
      expect(response.status).toBe(200);

      expect(calls.some((url) => url.endsWith('/push/register'))).toBe(true);

      const row = d1.raw.prepare('SELECT push_uuid FROM devices').get() as {
        push_uuid: string | null;
      };
      expect(row.push_uuid).not.toBeNull();
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it('clears the push token', async () => {
    await app.fetch(
      jsonRequest('/api/devices/identifier/device-1/token', { pushToken: 't' }, 'POST', token),
      env,
      executionContext,
    );

    const response = await app.fetch(
      new Request('https://example.com/api/devices/identifier/device-1/clear-token', {
        method: 'PUT',
        headers: { authorization: `Bearer ${token}` },
      }),
      env,
      executionContext,
    );
    expect(response.status).toBe(200);

    const row = d1.raw.prepare('SELECT push_token, push_uuid FROM devices').get() as {
      push_token: string | null;
      push_uuid: string | null;
    };
    expect(row.push_token).toBeNull();
    expect(row.push_uuid).toBeNull();
  });
});
