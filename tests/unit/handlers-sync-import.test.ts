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

beforeEach(async () => {
  d1 = createTestD1(schema);
  env = testEnv(d1) as unknown as Env;
  token = await registerAndLogin();
});

describe('sync', () => {
  it('returns the full sync envelope', async () => {
    const folder = (await (
      await app.fetch(
        jsonRequest('/api/folders', { name: '2.folder' }, 'POST', token),
        env,
        executionContext,
      )
    ).json()) as { id: string };

    await app.fetch(
      jsonRequest(
        '/api/ciphers',
        { type: 2, name: '2.note', folderId: folder.id, secureNote: { type: 0 } },
        'POST',
        token,
      ),
      env,
      executionContext,
    );

    const response = await app.fetch(getRequest('/api/sync', token), env, executionContext);
    expect(response.status).toBe(200);

    const body = (await response.json()) as Record<string, any>;
    expect(body.object).toBe('sync');
    expect(Object.keys(body)).toEqual([
      'profile',
      'folders',
      'collections',
      'policies',
      'ciphers',
      'domains',
      'sends',
      'userDecryption',
      'object',
    ]);
    expect(body.profile.object).toBe('profile');
    expect(body.profile.twoFactorEnabled).toBe(false);
    expect(body.folders).toHaveLength(1);
    expect(body.folders[0].object).toBe('folder');
    expect(body.ciphers).toHaveLength(1);
    expect(body.ciphers[0].folderId).toBe(folder.id);
    expect(body.collections).toEqual([]);
    expect(body.policies).toEqual([]);
    expect(body.sends).toEqual([]);
    expect(body.domains.object).toBe('domains');
    expect(body.domains.equivalentDomains).toEqual([]);
    expect(body.userDecryption.masterPasswordUnlock.salt).toBe(EMAIL);
  });

  it('nulls domains when excludeDomains=true', async () => {
    const response = await app.fetch(
      getRequest('/api/sync?excludeDomains=true', token),
      env,
      executionContext,
    );
    expect(((await response.json()) as { domains: unknown }).domains).toBeNull();
  });
});

describe('import', () => {
  it('imports folders and ciphers with relationships', async () => {
    const response = await app.fetch(
      jsonRequest(
        '/api/ciphers/import',
        {
          folders: [{ name: '2.imported-folder' }],
          ciphers: [
            { type: 2, name: '2.a', secureNote: { type: 0 } },
            { type: 1, name: '2.b', login: { username: 'u' } },
          ],
          folderRelationships: [{ key: 0, value: 0 }],
        },
        'POST',
        token,
      ),
      env,
      executionContext,
    );
    expect(response.status).toBe(200);
    expect(await response.text()).toBe('null');

    const folders = d1.raw.prepare('SELECT id, name FROM folders').all() as Array<{
      id: string;
      name: string;
    }>;
    expect(folders).toHaveLength(1);

    const ciphers = d1.raw.prepare('SELECT type, folder_id FROM ciphers').all() as Array<{
      type: number;
      folder_id: string | null;
    }>;
    expect(ciphers).toHaveLength(2);
    expect(ciphers.filter((row) => row.folder_id === folders[0]?.id)).toHaveLength(1);
  });
});

describe('domains settings', () => {
  it('returns and updates equivalent domains', async () => {
    const initial = await app.fetch(
      getRequest('/api/settings/domains', token),
      env,
      executionContext,
    );
    expect(initial.status).toBe(200);
    expect(await initial.json()).toEqual({
      equivalentDomains: [],
      globalEquivalentDomains: [],
      object: 'domains',
    });

    const update = await app.fetch(
      jsonRequest(
        '/api/settings/domains',
        {
          equivalentDomains: [['example.com', 'example.org']],
          excludedGlobalEquivalentDomains: [],
        },
        'PUT',
        token,
      ),
      env,
      executionContext,
    );
    expect(update.status).toBe(200);
    expect(await update.json()).toEqual({});

    const after = await app.fetch(
      getRequest('/api/settings/domains', token),
      env,
      executionContext,
    );
    expect(((await after.json()) as { equivalentDomains: unknown }).equivalentDomains).toEqual([
      ['example.com', 'example.org'],
    ]);
  });
});
