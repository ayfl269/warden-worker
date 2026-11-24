import { readFileSync } from 'node:fs';

import { beforeEach, describe, expect, it } from 'vitest';
import { makeApp } from '../../src/app';
import { base64UrlNoPadToBytes, bytesToBase64UrlNoPad } from '../../src/auth/base64';
import { pbkdf2Sha256 } from '../../src/auth/password';
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

function formRequest(path: string, form: Record<string, string>): Request {
  return new Request(`https://example.com${path}`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams(form).toString(),
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
    formRequest('/identity/connect/token', {
      grant_type: 'password',
      username: EMAIL,
      password: CLIENT_HASH,
      scope: 'api offline_access',
      client_id: 'cli',
      device_identifier: 'device-1',
      device_name: 'Device',
      device_type: '9',
    }),
    env,
    executionContext,
  );
  return ((await response.json()) as { access_token: string }).access_token;
}

async function createSend(
  overrides: Record<string, unknown> = {},
): Promise<Record<string, unknown>> {
  const response = await app.fetch(
    jsonRequest(
      '/api/sends',
      {
        type: 0,
        name: '2.send',
        key: '2.key',
        text: { text: '2.secret', hidden: false },
        maxAccessCount: null,
        deletionDate: new Date(Date.now() + 24 * 3600 * 1000).toISOString(),
        password: null,
        ...overrides,
      },
      'POST',
      token,
    ),
    env,
    executionContext,
  );
  return (await response.json()) as Record<string, unknown>;
}

beforeEach(async () => {
  d1 = createTestD1(schema);
  env = testEnv(d1) as unknown as Env;
  token = await registerAndLogin();
});

describe('send_access grant', () => {
  it('mints a 120s token and allows Bearer access', async () => {
    const send = await createSend();
    const accessId = send.accessId as string;

    const grant = await app.fetch(
      formRequest('/identity/connect/token', {
        grant_type: 'send_access',
        send_id: accessId,
        client_id: 'cli',
      }),
      env,
      executionContext,
    );
    expect(grant.status).toBe(200);

    const grantBody = (await grant.json()) as Record<string, unknown>;
    expect(grantBody.expires_in).toBe(120);
    expect(grantBody.token_type).toBe('Bearer');
    expect(grantBody.scope).toBe('api.send.access');

    const access = await app.fetch(
      new Request('https://example.com/api/sends/access', {
        method: 'POST',
        headers: { authorization: `Bearer ${grantBody.access_token as string}` },
      }),
      env,
      executionContext,
    );
    expect(access.status).toBe(200);

    const body = (await access.json()) as Record<string, unknown>;
    expect(body.object).toBe('send-access');
    expect(body.text).toEqual({ text: '2.secret', hidden: false });
  });

  it('requires a password hash for protected sends', async () => {
    const send = await createSend({ password: 'hunter2' });

    const missing = await app.fetch(
      formRequest('/identity/connect/token', {
        grant_type: 'send_access',
        send_id: send.accessId as string,
        client_id: 'cli',
      }),
      env,
      executionContext,
    );
    expect(missing.status).toBe(400);
    expect(await missing.json()).toEqual({
      kind: 'expected_server',
      error: 'invalid_request',
      send_access_error_type: 'password_hash_b64_required',
    });

    const wrong = await app.fetch(
      formRequest('/identity/connect/token', {
        grant_type: 'send_access',
        send_id: send.accessId as string,
        client_id: 'cli',
        password_hash_b64: 'bm90LXRoZS1yaWdodC1oYXNo',
      }),
      env,
      executionContext,
    );
    expect(wrong.status).toBe(400);
    expect(await wrong.json()).toEqual({
      kind: 'expected_server',
      error: 'invalid_grant',
      send_access_error_type: 'password_hash_b64_invalid',
    });
  });

  it('accepts the correct derived password hash', async () => {
    const send = await createSend({ password: 'hunter2' });

    const row = d1.raw.prepare('SELECT password_salt, password_iter FROM sends').get() as {
      password_salt: string;
      password_iter: number;
    };
    const derived = pbkdf2Sha256(
      new TextEncoder().encode('hunter2'),
      base64UrlNoPadToBytes(row.password_salt),
      row.password_iter,
    );

    const grant = await app.fetch(
      formRequest('/identity/connect/token', {
        grant_type: 'send_access',
        send_id: send.accessId as string,
        client_id: 'cli',
        password_hash_b64: bytesToBase64UrlNoPad(derived),
      }),
      env,
      executionContext,
    );
    expect(grant.status).toBe(200);
    expect(typeof ((await grant.json()) as { access_token: string }).access_token).toBe('string');
  });

  it('returns 400 for an unknown access id', async () => {
    const grant = await app.fetch(
      formRequest('/identity/connect/token', {
        grant_type: 'send_access',
        send_id: 'AAAAAAAAAAAAAAAAAAAAAA',
        client_id: 'cli',
      }),
      env,
      executionContext,
    );
    expect(grant.status).toBe(404);
  });
});
