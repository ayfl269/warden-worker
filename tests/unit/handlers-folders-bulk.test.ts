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

beforeEach(async () => {
  d1 = createTestD1(schema);
  env = testEnv(d1) as unknown as Env;
  token = await registerAndLogin();
});

describe('folders', () => {
  it('creates, lists, reads and updates a folder', async () => {
    const created = await app.fetch(
      jsonRequest('/api/folders', { name: '2.folder' }, 'POST', token),
      env,
      executionContext,
    );
    expect(created.status).toBe(200);
    const folder = (await created.json()) as Record<string, unknown>;
    expect(folder.object).toBe('folder');
    expect(folder.name).toBe('2.folder');
    const id = folder.id as string;

    const list = await app.fetch(getRequest('/api/folders', token), env, executionContext);
    const listBody = (await list.json()) as { data: Array<{ id: string }>; object: string };
    expect(listBody.object).toBe('list');
    expect(listBody.data.map((item) => item.id)).toEqual([id]);

    const single = await app.fetch(getRequest(`/api/folders/${id}`, token), env, executionContext);
    expect(single.status).toBe(200);

    const updated = await app.fetch(
      jsonRequest(`/api/folders/${id}`, { name: '2.renamed' }, 'PUT', token),
      env,
      executionContext,
    );
    expect(((await updated.json()) as { name: string }).name).toBe('2.renamed');
  });

  it('returns 400 for a missing folder on GET but 404 on PUT', async () => {
    const missing = '00000000-0000-4000-8000-000000000000';
    const get = await app.fetch(
      getRequest(`/api/folders/${missing}`, token),
      env,
      executionContext,
    );
    expect(get.status).toBe(400);
    expect(await get.json()).toEqual({
      error: 'Invalid folder: Folder does not exist or belongs to another user',
    });

    const put = await app.fetch(
      jsonRequest(`/api/folders/${missing}`, { name: 'x' }, 'PUT', token),
      env,
      executionContext,
    );
    expect(put.status).toBe(404);
    expect(await put.json()).toEqual({ error: 'Folder not found' });
  });

  it('deletes a folder without an existence check', async () => {
    const id = await createFolder('2.folder');
    const response = await app.fetch(
      new Request(`https://example.com/api/folders/${id}`, {
        method: 'DELETE',
        headers: { authorization: `Bearer ${token}` },
      }),
      env,
      executionContext,
    );
    expect(response.status).toBe(200);
    expect(await response.text()).toBe('null');
  });
});

describe('bulk cipher operations', () => {
  it('soft deletes and restores in bulk', async () => {
    const first = await createCipher('2.a');
    const second = await createCipher('2.b');

    const soft = await app.fetch(
      jsonRequest('/api/ciphers/delete', { ids: [first, second] }, 'PUT', token),
      env,
      executionContext,
    );
    expect(soft.status).toBe(200);

    const empty = await app.fetch(getRequest('/api/ciphers', token), env, executionContext);
    expect(((await empty.json()) as { data: unknown[] }).data).toHaveLength(0);

    const restored = await app.fetch(
      jsonRequest('/api/ciphers/restore', { ids: [first, second] }, 'PUT', token),
      env,
      executionContext,
    );
    const body = (await restored.json()) as { data: Array<{ id: string }> };
    expect(body.data.map((item) => item.id).sort()).toEqual([first, second].sort());
  });

  it('archives and unarchives in bulk', async () => {
    const id = await createCipher('2.a');

    const archived = await app.fetch(
      jsonRequest('/api/ciphers/archive', { ids: [id] }, 'PUT', token),
      env,
      executionContext,
    );
    const archivedBody = (await archived.json()) as {
      data: Array<{ archivedDate: string | null }>;
    };
    expect(archivedBody.data[0]?.archivedDate).not.toBeNull();

    const unarchived = await app.fetch(
      jsonRequest('/api/ciphers/unarchive', { ids: [id] }, 'PUT', token),
      env,
      executionContext,
    );
    const unarchivedBody = (await unarchived.json()) as {
      data: Array<{ archivedDate: string | null }>;
    };
    expect(unarchivedBody.data[0]?.archivedDate).toBeNull();
  });

  it('rejects archiving an unknown cipher with 400', async () => {
    const response = await app.fetch(
      jsonRequest('/api/ciphers/00000000-0000-4000-8000-000000000000/archive', {}, 'PUT', token),
      env,
      executionContext,
    );
    expect(response.status).toBe(400);
    expect(await response.json()).toEqual({
      error:
        'Cipher was not archived. Ensure the provided ID is correct and you have permission to archive it.',
    });
  });

  it('moves ciphers into a folder and validates ownership', async () => {
    const id = await createCipher('2.a');
    const folderId = await createFolder('2.folder');

    const moved = await app.fetch(
      jsonRequest('/api/ciphers/move', { folderId, ids: [id] }, 'POST', token),
      env,
      executionContext,
    );
    expect(moved.status).toBe(200);

    const row = d1.raw.prepare('SELECT folder_id FROM ciphers WHERE id = ?1').get(id) as {
      folder_id: string;
    };
    expect(row.folder_id).toBe(folderId);

    const invalid = await app.fetch(
      jsonRequest('/api/ciphers/move', { folderId: 'missing', ids: [id] }, 'POST', token),
      env,
      executionContext,
    );
    expect(invalid.status).toBe(400);
  });
});

describe('purge vault', () => {
  it('requires the master password and wipes ciphers and folders', async () => {
    await createCipher('2.a');
    await createFolder('2.folder');

    const missing = await app.fetch(
      jsonRequest('/api/ciphers/purge', {}, 'POST', token),
      env,
      executionContext,
    );
    expect(missing.status).toBe(400);

    const wrong = await app.fetch(
      jsonRequest('/api/ciphers/purge', { masterPasswordHash: 'nope' }, 'POST', token),
      env,
      executionContext,
    );
    expect(wrong.status).toBe(401);

    const ok = await app.fetch(
      jsonRequest('/api/ciphers/purge', { masterPasswordHash: CLIENT_HASH }, 'POST', token),
      env,
      executionContext,
    );
    expect(ok.status).toBe(200);

    const ciphers = d1.raw.prepare('SELECT COUNT(*) AS c FROM ciphers').get() as { c: number };
    const folders = d1.raw.prepare('SELECT COUNT(*) AS c FROM folders').get() as { c: number };
    expect(ciphers.c).toBe(0);
    expect(folders.c).toBe(0);
  });
});
