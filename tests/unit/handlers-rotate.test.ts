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

async function createCipher(name: string): Promise<string> {
  const response = await app.fetch(
    jsonRequest('/api/ciphers', { type: 2, name, secureNote: { type: 0 } }, 'POST', token),
    env,
    executionContext,
  );
  return ((await response.json()) as { id: string }).id;
}

async function createFolder(name: string): Promise<string> {
  const response = await app.fetch(
    jsonRequest('/api/folders', { name }, 'POST', token),
    env,
    executionContext,
  );
  return ((await response.json()) as { id: string }).id;
}

interface CipherRowRaw {
  id: string;
  type: number;
  data: string;
  folder_id: string | null;
  favorite: number;
}

function currentCiphers(): Array<Record<string, unknown>> {
  const rows = d1.raw
    .prepare('SELECT id, type, data, folder_id, favorite FROM ciphers')
    .all() as unknown as CipherRowRaw[];
  return rows.map((row) => ({
    id: row.id,
    type: row.type,
    folderId: row.folder_id,
    favorite: row.favorite === 1,
    ...(JSON.parse(row.data) as Record<string, unknown>),
  }));
}

function rotationBody(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    accountUnlockData: {
      masterPasswordUnlockData: {
        kdfType: 0,
        kdfIterations: 600000,
        kdfMemory: null,
        kdfParallelism: null,
        email: EMAIL,
        masterKeyAuthenticationHash: CLIENT_HASH,
        masterKeyEncryptedUserKey: 'new-user-key',
      },
    },
    accountKeys: {
      userKeyEncryptedAccountPrivateKey: 'new-private-key',
      accountPublicKey: 'pk',
    },
    accountData: {
      ciphers: currentCiphers(),
      folders: d1.raw
        .prepare('SELECT id FROM folders')
        .all()
        .map((row) => ({
          id: (row as { id: string }).id,
          name: '2.rotated',
        })),
      sends: [],
    },
    oldMasterKeyAuthenticationHash: CLIENT_HASH,
    ...overrides,
  };
}

async function rotate(body: Record<string, unknown>, bearer = token): Promise<Response> {
  return app.fetch(
    jsonRequest('/api/accounts/key-management/rotate-user-account-keys', body, 'POST', bearer),
    env,
    executionContext,
  );
}

beforeEach(async () => {
  d1 = createTestD1(schema);
  env = testEnv(d1) as unknown as Env;
  token = await registerAndLogin();
});

describe('key rotation', () => {
  it('rewrites ciphers, folders and account keys', async () => {
    await createCipher('2.a');
    await createCipher('2.b');
    await createFolder('2.folder');

    const ciphers = currentCiphers().map((cipher) => ({ ...cipher, name: '2.rotated' }));
    const body = rotationBody();
    (body.accountData as { ciphers: unknown }).ciphers = ciphers;
    const response = await rotate(body);
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({});

    const stored = d1.raw.prepare('SELECT data FROM ciphers').all() as Array<{ data: string }>;
    expect(stored.every((row) => JSON.parse(row.data).name === '2.rotated')).toBe(true);

    const folder = d1.raw.prepare('SELECT name FROM folders').get() as { name: string };
    expect(folder.name).toBe('2.rotated');

    const user = d1.raw.prepare('SELECT key, private_key, security_stamp FROM users').get() as {
      key: string;
      private_key: string;
      security_stamp: string;
    };
    expect(user.key).toBe('new-user-key');
    expect(user.private_key).toBe('new-private-key');

    const stale = await app.fetch(
      getRequest('/api/accounts/profile', token),
      env,
      executionContext,
    );
    expect(stale.status).toBe(401);
  });

  it('requires every existing cipher to be included', async () => {
    await createCipher('2.a');
    await createCipher('2.b');

    const partial = currentCiphers().slice(0, 1);
    const response = await rotate(
      rotationBody({
        accountData: { ciphers: partial, folders: [], sends: [] },
      }),
    );
    expect(response.status).toBe(400);
    expect(await response.json()).toEqual({
      error: 'All existing ciphers and folders must be included in the rotation',
    });
  });

  it('rejects a cipher without an id', async () => {
    await createCipher('2.a');
    const { id: _ignored, ...withoutId } = currentCiphers()[0] as Record<string, unknown>;

    const response = await rotate(
      rotationBody({ accountData: { ciphers: [withoutId], folders: [], sends: [] } }),
    );
    expect(response.status).toBe(400);
    expect(await response.json()).toEqual({
      error: 'All ciphers must have an id for key rotation',
    });
  });

  it('rejects an email or KDF change', async () => {
    const body = rotationBody();
    const unlock = (body.accountUnlockData as Record<string, any>).masterPasswordUnlockData;
    unlock.email = 'other@example.com';

    const response = await rotate(body);
    expect(response.status).toBe(400);
    expect(await response.json()).toEqual({
      error: 'Changing the kdf variant or email is not supported during key rotation',
    });
  });

  it('rejects a changed account public key', async () => {
    const body = rotationBody();
    (body.accountKeys as Record<string, unknown>).accountPublicKey = 'different';

    const response = await rotate(body);
    expect(response.status).toBe(400);
    expect(await response.json()).toEqual({
      error: 'Changing the asymmetric keypair is not supported during key rotation',
    });
  });

  it('rejects a wrong old master key hash', async () => {
    const response = await rotate(rotationBody({ oldMasterKeyAuthenticationHash: 'nope' }));
    expect(response.status).toBe(401);
    expect(await response.json()).toEqual({ error: 'Invalid password' });
  });
});
