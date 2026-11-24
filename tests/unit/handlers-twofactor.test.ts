import { readFileSync } from 'node:fs';

import { beforeEach, describe, expect, it } from 'vitest';
import { makeApp } from '../../src/app';
import { currentTotpTimeStep, generateTotp, generateTotpSecret } from '../../src/auth/totp';
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

function loginRequest(extra: Record<string, string> = {}): Request {
  return new Request('https://example.com/identity/connect/token', {
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
      ...extra,
    }).toString(),
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

  const response = await app.fetch(loginRequest(), env, executionContext);
  return ((await response.json()) as { access_token: string }).access_token;
}

beforeEach(async () => {
  d1 = createTestD1(schema);
  env = testEnv(d1) as unknown as Env;
  token = await registerAndLogin();
});

describe('two-factor listing', () => {
  it('starts empty', async () => {
    const response = await app.fetch(getRequest('/api/two-factor', token), env, executionContext);
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ data: [], object: 'list', continuationToken: null });
  });

  it('returns an unpersisted key before activation', async () => {
    const response = await app.fetch(
      jsonRequest(
        '/api/two-factor/get-authenticator',
        { masterPasswordHash: CLIENT_HASH },
        'POST',
        token,
      ),
      env,
      executionContext,
    );
    expect(response.status).toBe(200);
    const body = (await response.json()) as { enabled: boolean; key: string; object: string };
    expect(body.enabled).toBe(false);
    expect(body.object).toBe('twoFactorAuthenticator');
    expect(body.key).toHaveLength(32);

    const rows = d1.raw.prepare('SELECT COUNT(*) AS c FROM twofactor').get() as { c: number };
    expect(rows.c).toBe(0);
  });
});

describe('TOTP activation', () => {
  it('rejects a key that is not 20 bytes', async () => {
    const response = await app.fetch(
      jsonRequest(
        '/api/two-factor/authenticator',
        { masterPasswordHash: CLIENT_HASH, key: 'GEZDGNBV', token: '123456' },
        'POST',
        token,
      ),
      env,
      executionContext,
    );
    expect(response.status).toBe(400);
    expect(await response.json()).toEqual({ error: 'Invalid key length' });
  });

  it('activates TOTP, stores the key and creates a recovery code', async () => {
    const key = generateTotpSecret();
    const step = currentTotpTimeStep();
    const code = generateTotp(key, step);

    const response = await app.fetch(
      jsonRequest(
        '/api/two-factor/authenticator',
        { masterPasswordHash: CLIENT_HASH, key: key.toLowerCase(), token: code },
        'POST',
        token,
      ),
      env,
      executionContext,
    );
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({
      enabled: true,
      key,
      object: 'twoFactorAuthenticator',
    });

    const row = d1.raw.prepare('SELECT atype, data, last_used FROM twofactor').get() as {
      atype: number;
      data: string;
      last_used: number;
    };
    expect(row.atype).toBe(0);
    expect(row.data).toBe(key);
    // The handler stores the time step it validated against. The 30 s window can
    // roll over between generating the code above and handling the request, so
    // accept either the current step or the next one.
    expect([step, step + 1]).toContain(row.last_used);

    const user = d1.raw.prepare('SELECT totp_recover FROM users').get() as {
      totp_recover: string | null;
    };
    expect(user.totp_recover).toHaveLength(32);
  });

  it('makes the next login require a second factor', async () => {
    const key = generateTotpSecret();
    await app.fetch(
      jsonRequest(
        '/api/two-factor/authenticator',
        { masterPasswordHash: CLIENT_HASH, key, token: generateTotp(key, currentTotpTimeStep()) },
        'POST',
        token,
      ),
      env,
      executionContext,
    );

    const response = await app.fetch(loginRequest(), env, executionContext);
    expect(response.status).toBe(400);
    expect(await response.json()).toEqual({
      error: 'invalid_grant',
      error_description: 'Two factor required.',
      TwoFactorProviders: ['0'],
      TwoFactorProviders2: { 0: null },
      MasterPasswordPolicy: { Object: 'masterPasswordPolicy' },
    });
  });

  it('accepts a login that supplies a fresh TOTP code', async () => {
    const key = generateTotpSecret();
    await app.fetch(
      jsonRequest(
        '/api/two-factor/authenticator',
        { masterPasswordHash: CLIENT_HASH, key, token: generateTotp(key, currentTotpTimeStep()) },
        'POST',
        token,
      ),
      env,
      executionContext,
    );

    // Activation consumed the current step; simulate time moving forward.
    d1.raw.prepare('UPDATE twofactor SET last_used = 0').run();

    const response = await app.fetch(
      loginRequest({
        twoFactorProvider: '0',
        twoFactorToken: generateTotp(key, currentTotpTimeStep()),
      }),
      env,
      executionContext,
    );
    expect(response.status).toBe(200);
    expect(typeof ((await response.json()) as { access_token: string }).access_token).toBe(
      'string',
    );
  });

  it('issues and persists a remember token when requested', async () => {
    const key = generateTotpSecret();
    await app.fetch(
      jsonRequest(
        '/api/two-factor/authenticator',
        { masterPasswordHash: CLIENT_HASH, key, token: generateTotp(key, currentTotpTimeStep()) },
        'POST',
        token,
      ),
      env,
      executionContext,
    );
    d1.raw.prepare('UPDATE twofactor SET last_used = 0').run();

    const response = await app.fetch(
      loginRequest({
        twoFactorProvider: '0',
        twoFactorToken: generateTotp(key, currentTotpTimeStep()),
        twoFactorRemember: '1',
      }),
      env,
      executionContext,
    );
    expect(response.status).toBe(200);

    const body = (await response.json()) as { TwoFactorToken?: string };
    expect(typeof body.TwoFactorToken).toBe('string');

    const row = d1.raw.prepare('SELECT twofactor_remember FROM devices').get() as {
      twofactor_remember: string | null;
    };
    expect(row.twofactor_remember).toBe(body.TwoFactorToken);
  });

  it('rejects a wrong TOTP code with 401', async () => {
    const key = generateTotpSecret();
    await app.fetch(
      jsonRequest(
        '/api/two-factor/authenticator',
        { masterPasswordHash: CLIENT_HASH, key, token: generateTotp(key, currentTotpTimeStep()) },
        'POST',
        token,
      ),
      env,
      executionContext,
    );
    d1.raw.prepare('UPDATE twofactor SET last_used = 0').run();

    const response = await app.fetch(
      loginRequest({ twoFactorProvider: '0', twoFactorToken: '000000' }),
      env,
      executionContext,
    );
    expect(response.status).toBe(401);
    expect(await response.json()).toEqual({ error: 'Invalid TOTP code.' });
  });
});

describe('disable and recovery', () => {
  it('returns the recovery code', async () => {
    const key = generateTotpSecret();
    await app.fetch(
      jsonRequest(
        '/api/two-factor/authenticator',
        { masterPasswordHash: CLIENT_HASH, key, token: generateTotp(key, currentTotpTimeStep()) },
        'POST',
        token,
      ),
      env,
      executionContext,
    );

    const response = await app.fetch(
      jsonRequest(
        '/api/two-factor/get-recover',
        { masterPasswordHash: CLIENT_HASH },
        'POST',
        token,
      ),
      env,
      executionContext,
    );
    expect(response.status).toBe(200);
    const body = (await response.json()) as { code: string; object: string };
    expect(body.object).toBe('twoFactorRecover');
    expect(body.code).toHaveLength(32);
  });

  it('disables TOTP and clears the recovery code', async () => {
    const key = generateTotpSecret();
    await app.fetch(
      jsonRequest(
        '/api/two-factor/authenticator',
        { masterPasswordHash: CLIENT_HASH, key, token: generateTotp(key, currentTotpTimeStep()) },
        'POST',
        token,
      ),
      env,
      executionContext,
    );

    const response = await app.fetch(
      jsonRequest(
        '/api/two-factor/disable',
        { masterPasswordHash: CLIENT_HASH, type: 0 },
        'POST',
        token,
      ),
      env,
      executionContext,
    );
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({
      enabled: false,
      type: 0,
      object: 'twoFactorProvider',
    });

    const rows = d1.raw.prepare('SELECT COUNT(*) AS c FROM twofactor').get() as { c: number };
    expect(rows.c).toBe(0);
    const user = d1.raw.prepare('SELECT totp_recover FROM users').get() as {
      totp_recover: string | null;
    };
    expect(user.totp_recover).toBeNull();
  });

  it('rejects deleting an authenticator with a mismatched key', async () => {
    const key = generateTotpSecret();
    await app.fetch(
      jsonRequest(
        '/api/two-factor/authenticator',
        { masterPasswordHash: CLIENT_HASH, key, token: generateTotp(key, currentTotpTimeStep()) },
        'POST',
        token,
      ),
      env,
      executionContext,
    );

    const response = await app.fetch(
      jsonRequest(
        '/api/two-factor/authenticator',
        { masterPasswordHash: CLIENT_HASH, key: generateTotpSecret(), type: 0 },
        'DELETE',
        token,
      ),
      env,
      executionContext,
    );
    expect(response.status).toBe(400);
    expect(await response.json()).toEqual({ error: 'TOTP key does not match recorded value' });
  });
});
