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

function sendBody(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    type: 0,
    name: '2.send',
    notes: null,
    key: '2.key',
    text: { text: '2.secret', hidden: false },
    maxAccessCount: null,
    deletionDate: new Date(Date.now() + 7 * 24 * 3600 * 1000).toISOString(),
    expirationDate: null,
    disabled: false,
    hideEmail: false,
    password: null,
    ...overrides,
  };
}

async function createSend(
  overrides: Record<string, unknown> = {},
): Promise<Record<string, unknown>> {
  const response = await app.fetch(
    jsonRequest('/api/sends', sendBody(overrides), 'POST', token),
    env,
    executionContext,
  );
  const text = await response.text();
  try {
    return JSON.parse(text) as Record<string, unknown>;
  } catch {
    throw new Error(`createSend failed (${response.status}): ${text}`);
  }
}

beforeEach(async () => {
  d1 = createTestD1(schema);
  env = testEnv(d1) as unknown as Env;
  token = await registerAndLogin();
});

describe('text send lifecycle', () => {
  it('creates, lists, reads, updates and deletes', async () => {
    const created = await createSend();
    expect(created.object).toBe('send');
    expect(created.type).toBe(0);
    expect(created.name).toBe('2.send');
    expect(created.text).toEqual({ text: '2.secret', hidden: false });
    expect(created.file).toBeNull();
    expect(created.accessCount).toBe(0);
    expect(created.authType).toBe(2);
    expect(typeof created.accessId).toBe('string');

    const list = await app.fetch(getRequest('/api/sends', token), env, executionContext);
    expect(((await list.json()) as { data: unknown[] }).data).toHaveLength(1);

    const id = created.id as string;
    const single = await app.fetch(getRequest(`/api/sends/${id}`, token), env, executionContext);
    expect(((await single.json()) as { id: string }).id).toBe(id);

    const updated = await app.fetch(
      jsonRequest(`/api/sends/${id}`, { name: '2.renamed' }, 'PUT', token),
      env,
      executionContext,
    );
    expect(((await updated.json()) as { name: string }).name).toBe('2.renamed');

    const deleted = await app.fetch(
      new Request(`https://example.com/api/sends/${id}`, {
        method: 'DELETE',
        headers: { authorization: `Bearer ${token}` },
      }),
      env,
      executionContext,
    );
    expect(deleted.status).toBe(200);
    expect(await deleted.text()).toBe('""');
  });

  it('rejects a file send through the text endpoint', async () => {
    const response = await app.fetch(
      jsonRequest('/api/sends', sendBody({ type: 1 }), 'POST', token),
      env,
      executionContext,
    );
    expect(response.status).toBe(400);
    expect(await response.json()).toEqual({ error: 'Use /api/sends/file/v2 for file sends' });
  });

  it('rejects a deletion date beyond 31 days', async () => {
    const response = await app.fetch(
      jsonRequest(
        '/api/sends',
        sendBody({ deletionDate: new Date(Date.now() + 40 * 24 * 3600 * 1000).toISOString() }),
        'POST',
        token,
      ),
      env,
      executionContext,
    );
    expect(response.status).toBe(400);
    expect(await response.json()).toEqual({ error: 'Deletion date must be within 31 days' });
  });

  it('rejects text larger than the configured limit', async () => {
    env = { ...env, SEND_TEXT_MAX_BYTES: '32' } as unknown as Env;
    const response = await app.fetch(
      jsonRequest('/api/sends', sendBody({ text: { text: 'x'.repeat(64) } }), 'POST', token),
      env,
      executionContext,
    );
    expect(response.status).toBe(400);
  });
});

describe('anonymous access', () => {
  it('returns the send-access payload and counts the access', async () => {
    const created = await createSend();
    const accessId = created.accessId as string;

    const response = await app.fetch(
      new Request(`https://example.com/api/sends/access/${accessId}`, { method: 'POST' }),
      env,
      executionContext,
    );
    expect(response.status).toBe(200);

    const body = (await response.json()) as Record<string, unknown>;
    expect(body.object).toBe('send-access');
    expect(body.creatorIdentifier).toBe(EMAIL);
    expect(body.text).toEqual({ text: '2.secret', hidden: false });

    const row = d1.raw.prepare('SELECT access_count FROM sends').get() as { access_count: number };
    expect(row.access_count).toBe(1);
  });

  it('enforces the password and max access count', async () => {
    const created = await createSend({ password: 'hunter2', maxAccessCount: 1 });
    const accessId = created.accessId as string;

    const missing = await app.fetch(
      jsonRequest(`/api/sends/access/${accessId}`, {}, 'POST'),
      env,
      executionContext,
    );
    expect(missing.status).toBe(401);
    expect(await missing.json()).toEqual({ error: 'Password not provided' });

    const wrong = await app.fetch(
      jsonRequest(`/api/sends/access/${accessId}`, { password: 'nope' }, 'POST'),
      env,
      executionContext,
    );
    expect(wrong.status).toBe(400);
    expect(await wrong.json()).toEqual({ error: 'Invalid password' });

    const ok = await app.fetch(
      jsonRequest(`/api/sends/access/${accessId}`, { password: 'hunter2' }, 'POST'),
      env,
      executionContext,
    );
    expect(ok.status).toBe(200);

    const exhausted = await app.fetch(
      jsonRequest(`/api/sends/access/${accessId}`, { password: 'hunter2' }, 'POST'),
      env,
      executionContext,
    );
    expect(exhausted.status).toBe(404);
    expect(await exhausted.json()).toEqual({
      error: 'Send does not exist or is no longer available',
    });
  });

  it('hides the creator email when hideEmail is set', async () => {
    const created = await createSend({ hideEmail: true });
    const response = await app.fetch(
      new Request(`https://example.com/api/sends/access/${created.accessId as string}`, {
        method: 'POST',
      }),
      env,
      executionContext,
    );
    expect(
      ((await response.json()) as { creatorIdentifier: unknown }).creatorIdentifier,
    ).toBeNull();
  });

  it('returns 404 for an unknown access id', async () => {
    const response = await app.fetch(
      new Request('https://example.com/api/sends/access/AAAAAAAAAAAAAAAAAAAAAA', {
        method: 'POST',
      }),
      env,
      executionContext,
    );
    expect(response.status).toBe(404);
  });
});
