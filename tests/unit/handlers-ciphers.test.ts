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

async function createCipher(body: Record<string, unknown> = {}): Promise<Record<string, unknown>> {
  const response = await app.fetch(
    jsonRequest(
      '/api/ciphers',
      { type: 2, name: '2.note', notes: '2.notes', secureNote: { type: 0 }, ...body },
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

describe('cipher creation', () => {
  it('returns cipherDetails and stores the data blob', async () => {
    const created = await createCipher();
    expect(created.object).toBe('cipher');
    expect(created.type).toBe(2);
    expect(created.name).toBe('2.note');
    expect(created.notes).toBe('2.notes');
    expect(created.secureNote).toEqual({ type: 0 });
    expect(created.login).toBeNull();
    expect(created.card).toBeNull();
    expect(created.favorite).toBe(false);
    expect(created.collectionIds).toEqual([]);
    expect(created.permissions).toEqual({ delete: true, restore: true });
    expect(created.deletedDate).toBeNull();
    expect(created.archivedDate).toBeNull();

    const row = d1.raw.prepare('SELECT data FROM ciphers').get() as { data: string };
    expect(JSON.parse(row.data)).toEqual({
      name: '2.note',
      notes: '2.notes',
      secureNote: { type: 0 },
    });
  });

  it('accepts the {cipher: ...} wrapper on /create', async () => {
    const response = await app.fetch(
      jsonRequest(
        '/api/ciphers/create',
        { cipher: { type: 1, name: '2.login', login: { username: 'u' } }, collectionIds: [] },
        'POST',
        token,
      ),
      env,
      executionContext,
    );
    expect(response.status).toBe(200);
    const body = (await response.json()) as Record<string, unknown>;
    expect(body.login).toEqual({ username: 'u' });
    expect(body.secureNote).toBeNull();
  });

  it('rejects an unknown folder', async () => {
    const response = await app.fetch(
      jsonRequest('/api/ciphers', { type: 2, name: 'n', folderId: 'missing' }, 'POST', token),
      env,
      executionContext,
    );
    expect(response.status).toBe(400);
    expect(await response.json()).toEqual({
      error: 'Invalid folder: Folder does not exist or belongs to another user',
    });
  });
});

describe('cipher reads', () => {
  it('lists and fetches a cipher', async () => {
    const created = await createCipher();
    const id = created.id as string;

    const list = await app.fetch(getRequest('/api/ciphers', token), env, executionContext);
    const listBody = (await list.json()) as { data: Array<{ id: string }>; object: string };
    expect(listBody.object).toBe('list');
    expect(listBody.data.map((item) => item.id)).toEqual([id]);

    const single = await app.fetch(getRequest(`/api/ciphers/${id}`, token), env, executionContext);
    expect(((await single.json()) as { id: string }).id).toBe(id);
  });

  it('returns 404 for an unknown cipher', async () => {
    const response = await app.fetch(
      getRequest('/api/ciphers/00000000-0000-4000-8000-000000000000', token),
      env,
      executionContext,
    );
    expect(response.status).toBe(404);
    expect(await response.json()).toEqual({ error: 'Cipher not found' });
  });
});

describe('cipher updates', () => {
  it('updates the encrypted data and revision date', async () => {
    const created = await createCipher();
    const id = created.id as string;

    const response = await app.fetch(
      jsonRequest(
        `/api/ciphers/${id}`,
        { type: 2, name: '2.updated', notes: null, secureNote: { type: 0 } },
        'PUT',
        token,
      ),
      env,
      executionContext,
    );
    expect(response.status).toBe(200);

    const body = (await response.json()) as Record<string, unknown>;
    expect(body.name).toBe('2.updated');
    expect(body.notes).toBeNull();
    expect(body.revisionDate).not.toBe(created.revisionDate);
  });

  it('rejects a stale lastKnownRevisionDate', async () => {
    const created = await createCipher();
    const id = created.id as string;

    const response = await app.fetch(
      jsonRequest(
        `/api/ciphers/${id}`,
        {
          type: 2,
          name: 'n',
          lastKnownRevisionDate: '2020-01-01T00:00:00.000Z',
        },
        'PUT',
        token,
      ),
      env,
      executionContext,
    );
    expect(response.status).toBe(400);
    expect(await response.json()).toEqual({
      error: 'The client copy of this cipher is out of date. Resync the client and try again.',
    });
  });

  it('toggles favorite through /partial', async () => {
    const created = await createCipher();
    const id = created.id as string;

    const response = await app.fetch(
      jsonRequest(`/api/ciphers/${id}/partial`, { favorite: true }, 'PUT', token),
      env,
      executionContext,
    );
    expect(response.status).toBe(200);
    expect(((await response.json()) as { favorite: boolean }).favorite).toBe(true);
  });
});

describe('cipher deletion lifecycle', () => {
  it('soft deletes, restores and hard deletes', async () => {
    const created = await createCipher();
    const id = created.id as string;

    const soft = await app.fetch(
      jsonRequest(`/api/ciphers/${id}/delete`, {}, 'PUT', token),
      env,
      executionContext,
    );
    expect(soft.status).toBe(200);
    expect(await soft.text()).toBe('null');

    const hidden = await app.fetch(getRequest('/api/ciphers', token), env, executionContext);
    expect(((await hidden.json()) as { data: unknown[] }).data).toHaveLength(0);

    const trashed = await app.fetch(getRequest(`/api/ciphers/${id}`, token), env, executionContext);
    expect(((await trashed.json()) as { deletedDate: string | null }).deletedDate).not.toBeNull();

    const restored = await app.fetch(
      jsonRequest(`/api/ciphers/${id}/restore`, {}, 'PUT', token),
      env,
      executionContext,
    );
    expect(((await restored.json()) as { deletedDate: string | null }).deletedDate).toBeNull();

    const hard = await app.fetch(
      new Request(`https://example.com/api/ciphers/${id}`, {
        method: 'DELETE',
        headers: { authorization: `Bearer ${token}` },
      }),
      env,
      executionContext,
    );
    expect(hard.status).toBe(200);

    const gone = await app.fetch(getRequest(`/api/ciphers/${id}`, token), env, executionContext);
    expect(gone.status).toBe(404);
  });
});
