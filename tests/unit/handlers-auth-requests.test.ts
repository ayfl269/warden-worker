import { readFileSync } from 'node:fs';

import { beforeEach, describe, expect, it } from 'vitest';

import { makeApp } from '../../src/app';
import type { Env } from '../../src/env';
import { decodeFanoutMessage } from '../../src/notifications/connection';
import { createTestD1, type TestD1, testEnv } from '../helpers/sqlite-d1';

const schema = readFileSync('sql/schema.sql', 'utf8');
const CLIENT_HASH = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=';
const EMAIL = 'user@example.com';
const ACCESS_CODE = 'access-code-123';

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

function createRequest(bearer: string, deviceType = '9'): Request {
  return new Request('https://example.com/api/auth-requests', {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      authorization: `Bearer ${bearer}`,
      'device-type': deviceType,
    },
    body: JSON.stringify({
      accessCode: ACCESS_CODE,
      deviceIdentifier: 'device-1',
      email: EMAIL,
      publicKey: 'request-public-key',
    }),
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

describe('create auth request', () => {
  it('creates a pending request with the display device type', async () => {
    const response = await app.fetch(createRequest(token), env, executionContext);
    expect(response.status).toBe(200);

    const body = (await response.json()) as Record<string, unknown>;
    expect(body.object).toBe('auth-request');
    expect(body.requestDeviceType).toBe('Chrome');
    expect(body.requestIpAddress).toBe('unknown');
    expect(body.requestApproved).toBe(false);
    expect(body.key).toBeNull();
    expect(body.origin).toBe('https://example.com');

    const row = d1.raw.prepare('SELECT approved, access_code FROM auth_requests').get() as {
      approved: number | null;
      access_code: string;
    };
    expect(row.approved).toBeNull();
    expect(row.access_code).toBe(ACCESS_CODE);
  });

  it('rejects a mismatched device type', async () => {
    const response = await app.fetch(createRequest(token, '1'), env, executionContext);
    expect(response.status).toBe(400);
    expect(await response.json()).toEqual({ error: "AuthRequest doesn't exist" });
  });

  it('rejects an unknown email', async () => {
    const response = await app.fetch(
      new Request('https://example.com/api/auth-requests', {
        method: 'POST',
        headers: { 'content-type': 'application/json', authorization: `Bearer ${token}` },
        body: JSON.stringify({
          accessCode: ACCESS_CODE,
          deviceIdentifier: 'device-1',
          email: 'nobody@example.com',
          publicKey: 'pk',
        }),
      }),
      env,
      executionContext,
    );
    expect(response.status).toBe(400);
    expect(await response.json()).toEqual({ error: "AuthRequest doesn't exist" });
  });
});

describe('pending list', () => {
  it('lists the pending request', async () => {
    const created = (await (
      await app.fetch(createRequest(token), env, executionContext)
    ).json()) as { id: string };

    const response = await app.fetch(
      new Request('https://example.com/api/auth-requests/pending', {
        headers: { authorization: `Bearer ${token}` },
      }),
      env,
      executionContext,
    );
    expect(response.status).toBe(200);

    const body = (await response.json()) as { data: Array<{ id: string }>; object: string };
    expect(body.object).toBe('list');
    expect(body.data.map((item) => item.id)).toContain(created.id);
  });
});

describe('approve', () => {
  it('approves the request and stores the encrypted key', async () => {
    const created = (await (
      await app.fetch(createRequest(token), env, executionContext)
    ).json()) as { id: string };

    const response = await app.fetch(
      jsonRequest(
        `/api/auth-requests/${created.id}`,
        {
          deviceIdentifier: 'device-1',
          key: 'encrypted-key',
          masterPasswordHash: CLIENT_HASH,
          requestApproved: true,
        },
        'PUT',
        token,
      ),
      env,
      executionContext,
    );
    expect(response.status).toBe(200);

    const body = (await response.json()) as Record<string, unknown>;
    expect(body.requestApproved).toBe(true);
    expect(body.key).toBe('encrypted-key');
    expect(body.responseDate).not.toBeNull();
  });

  it('rejects approval from a different device', async () => {
    const created = (await (
      await app.fetch(createRequest(token), env, executionContext)
    ).json()) as { id: string };

    const response = await app.fetch(
      jsonRequest(
        `/api/auth-requests/${created.id}`,
        { deviceIdentifier: 'other', key: 'k', requestApproved: true },
        'PUT',
        token,
      ),
      env,
      executionContext,
    );
    expect(response.status).toBe(400);
  });
});

describe('response polling', () => {
  it('returns the request only for the matching device type, IP and code', async () => {
    const created = (await (
      await app.fetch(createRequest(token), env, executionContext)
    ).json()) as { id: string };

    const ok = await app.fetch(
      new Request(
        `https://example.com/api/auth-requests/${created.id}/response?code=${ACCESS_CODE}`,
        { headers: { 'device-type': '9' } },
      ),
      env,
      executionContext,
    );
    expect(ok.status).toBe(200);
    expect(((await ok.json()) as { id: string }).id).toBe(created.id);

    const wrongCode = await app.fetch(
      new Request(`https://example.com/api/auth-requests/${created.id}/response?code=nope`, {
        headers: { 'device-type': '9' },
      }),
      env,
      executionContext,
    );
    expect(wrongCode.status).toBe(400);

    const wrongType = await app.fetch(
      new Request(
        `https://example.com/api/auth-requests/${created.id}/response?code=${ACCESS_CODE}`,
        { headers: { 'device-type': '1' } },
      ),
      env,
      executionContext,
    );
    expect(wrongType.status).toBe(400);
  });
});

describe('auth request notifications', () => {
  it('publishes the request and the anonymous approval response', async () => {
    const captured: Array<{ selector: unknown; text: string }> = [];
    const stub = {
      async fetch(_input: RequestInfo | URL, init?: RequestInit) {
        const body = JSON.parse(String(init?.body ?? '{}')) as {
          selector?: unknown;
          message?: string;
        };
        const bytes = decodeFanoutMessage(body.message ?? '');
        if (bytes !== null) {
          captured.push({ selector: body.selector, text: new TextDecoder().decode(bytes) });
        }
        return new Response('{}');
      },
    };
    env = {
      ...env,
      NOTIFY_DO: { idFromName: (name: string) => name, get: () => stub },
    } as unknown as Env;

    const created = (await (
      await app.fetch(createRequest(token), env, executionContext)
    ).json()) as { id: string };
    await new Promise((resolve) => setTimeout(resolve, 10));

    expect(captured).toHaveLength(1);
    expect(captured[0]?.selector).toEqual({ kind: 'by_user', user_id: expect.any(String) });
    // The update type is an integer (15), so assert the envelope and context instead.
    expect(captured[0]?.text).toContain('ReceiveMessage');
    expect(captured[0]?.text).toContain('device-1');
    expect(captured[0]?.text).toContain('Payload');

    await app.fetch(
      jsonRequest(
        `/api/auth-requests/${created.id}`,
        { deviceIdentifier: 'device-1', key: 'encrypted-key', requestApproved: true },
        'PUT',
        token,
      ),
      env,
      executionContext,
    );
    await new Promise((resolve) => setTimeout(resolve, 10));

    expect(captured).toHaveLength(3);
    const anonymous = captured.find(
      (entry) => (entry.selector as { kind?: string }).kind === 'by_anonymous_token',
    );
    expect(anonymous?.text).toContain('AuthRequestResponseRecieved');
    expect(captured.some((entry) => entry.text.includes('ReceiveMessage'))).toBe(true);
  });
});
