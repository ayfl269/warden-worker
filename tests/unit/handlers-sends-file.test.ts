import { readFileSync } from 'node:fs';

import { beforeEach, describe, expect, it } from 'vitest';

import { makeApp } from '../../src/app';
import type { Env } from '../../src/env';
import { handleStreaming } from '../../src/handlers/streaming';
import { FakeR2Bucket } from '../helpers/fake-storage';
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

describe('file sends', () => {
  it('creates, uploads, grants access and downloads', async () => {
    const bucket = new FakeR2Bucket();
    env = { ...env, ATTACHMENTS_BUCKET: bucket } as unknown as Env;

    const created = await app.fetch(
      jsonRequest(
        '/api/sends/file/v2',
        {
          type: 1,
          name: '2.file',
          notes: null,
          key: '2.key',
          file: { fileName: 'f.bin' },
          fileLength: 5,
          maxAccessCount: null,
          deletionDate: new Date(Date.now() + 24 * 3600 * 1000).toISOString(),
          expirationDate: null,
          disabled: false,
          hideEmail: false,
          password: null,
        },
        'POST',
        token,
      ),
      env,
      executionContext,
    );
    expect(created.status).toBe(200);

    const body = (await created.json()) as {
      object: string;
      url: string;
      fileUploadType: number;
      sendResponse: { id: string; file: { id: string; size: string; sizeName: string } };
    };
    expect(body.object).toBe('send-fileUpload');
    expect(body.fileUploadType).toBe(1);
    expect(body.sendResponse.file.size).toBe('5');
    expect(body.sendResponse.file.sizeName).toBe('5.00 B');

    const sendId = body.sendResponse.id;
    const fileId = body.sendResponse.file.id;

    const uploadUrl = new URL(body.url);
    const upload = await handleStreaming(
      new Request(uploadUrl, { method: 'PUT', body: 'hello', headers: { 'content-length': '5' } }),
      env,
      uploadUrl,
    );
    expect(upload.status).toBe(201);

    const pending = d1.raw.prepare('SELECT COUNT(*) AS c FROM sends_pending').get() as {
      c: number;
    };
    const committed = d1.raw.prepare('SELECT COUNT(*) AS c FROM sends').get() as { c: number };
    expect(pending.c).toBe(0);
    expect(committed.c).toBe(1);
    expect(bucket.store.get(`sends/${sendId}/${fileId}`)).toBeDefined();

    const access = await app.fetch(
      new Request(`https://example.com/api/sends/${sendId}/access/file/${fileId}`, {
        method: 'POST',
      }),
      env,
      executionContext,
    );
    expect(access.status).toBe(200);
    const accessBody = (await access.json()) as { object: string; url: string; id: string };
    expect(accessBody.object).toBe('send-fileDownload');
    expect(accessBody.id).toBe(fileId);

    const downloadUrl = new URL(accessBody.url);
    const download = await handleStreaming(new Request(downloadUrl), env, downloadUrl);
    expect(download.status).toBe(200);
    expect(await download.text()).toBe('hello');

    const deleted = await app.fetch(
      new Request(`https://example.com/api/sends/${sendId}`, {
        method: 'DELETE',
        headers: { authorization: `Bearer ${token}` },
      }),
      env,
      executionContext,
    );
    expect(deleted.status).toBe(200);
    expect(bucket.store.size).toBe(0);
  });

  it('rejects file sends without a storage backend', async () => {
    const response = await app.fetch(
      jsonRequest(
        '/api/sends/file/v2',
        {
          type: 1,
          name: '2.file',
          key: 'k',
          file: { fileName: 'f' },
          fileLength: 5,
          deletionDate: new Date(Date.now() + 24 * 3600 * 1000).toISOString(),
        },
        'POST',
        token,
      ),
      env,
      executionContext,
    );
    expect(response.status).toBe(400);
    expect(await response.json()).toEqual({ error: 'File storage is not enabled' });
  });

  it('rejects a negative length', async () => {
    env = { ...env, ATTACHMENTS_BUCKET: new FakeR2Bucket() } as unknown as Env;
    const response = await app.fetch(
      jsonRequest(
        '/api/sends/file/v2',
        {
          type: 1,
          name: '2.file',
          key: 'k',
          file: { fileName: 'f' },
          fileLength: -1,
          deletionDate: new Date(Date.now() + 24 * 3600 * 1000).toISOString(),
        },
        'POST',
        token,
      ),
      env,
      executionContext,
    );
    expect(response.status).toBe(400);
    expect(await response.json()).toEqual({ error: "Send size can't be negative" });
  });

  it('rejects a download with an invalid token', async () => {
    env = { ...env, ATTACHMENTS_BUCKET: new FakeR2Bucket() } as unknown as Env;
    const url = new URL('https://example.com/api/sends/s1/f1?t=bad');
    const response = await handleStreaming(new Request(url), env, url);
    expect(response.status).toBe(404);
  });
});

describe('multipart compatibility endpoints', () => {
  it('creates a file send through the legacy multipart endpoint', async () => {
    const bucket = new FakeR2Bucket();
    env = { ...env, ATTACHMENTS_BUCKET: bucket } as unknown as Env;

    const form = new FormData();
    form.append(
      'model',
      JSON.stringify({
        type: 1,
        name: '2.legacy',
        key: '2.key',
        file: { fileName: 'f.bin' },
        deletionDate: new Date(Date.now() + 24 * 3600 * 1000).toISOString(),
        password: null,
      }),
    );
    form.append('data', new File([new Uint8Array([1, 2, 3, 4, 5])], 'f.bin'));

    const response = await app.fetch(
      new Request('https://example.com/api/sends/file', {
        method: 'POST',
        headers: { authorization: `Bearer ${token}` },
        body: form,
      }),
      env,
      executionContext,
    );
    expect(response.status).toBe(200);

    const body = (await response.json()) as { id: string; file: { size: string } };
    expect(body.file.size).toBe('5');

    const committed = d1.raw.prepare('SELECT COUNT(*) AS c FROM sends').get() as { c: number };
    expect(committed.c).toBe(1);
    expect(bucket.store.size).toBe(1);
  });

  it('accepts a direct multipart upload for a pending file send', async () => {
    const bucket = new FakeR2Bucket();
    env = { ...env, ATTACHMENTS_BUCKET: bucket } as unknown as Env;

    const created = (await (
      await app.fetch(
        jsonRequest(
          '/api/sends/file/v2',
          {
            type: 1,
            name: '2.file',
            key: '2.key',
            file: { fileName: 'f.bin' },
            fileLength: 5,
            deletionDate: new Date(Date.now() + 24 * 3600 * 1000).toISOString(),
            password: null,
          },
          'POST',
          token,
        ),
        env,
        executionContext,
      )
    ).json()) as { sendResponse: { id: string; file: { id: string } } };

    const sendId = created.sendResponse.id;
    const fileId = created.sendResponse.file.id;

    const form = new FormData();
    form.append('data', new File([new Uint8Array([1, 2, 3, 4, 5])], 'f.bin'));

    const response = await app.fetch(
      new Request(`https://example.com/api/sends/${sendId}/file/${fileId}`, {
        method: 'POST',
        headers: { authorization: `Bearer ${token}` },
        body: form,
      }),
      env,
      executionContext,
    );
    expect(response.status).toBe(200);
    expect(await response.text()).toBe('null');

    const pending = d1.raw.prepare('SELECT COUNT(*) AS c FROM sends_pending').get() as {
      c: number;
    };
    const committed = d1.raw.prepare('SELECT COUNT(*) AS c FROM sends').get() as { c: number };
    expect(pending.c).toBe(0);
    expect(committed.c).toBe(1);
  });
});
