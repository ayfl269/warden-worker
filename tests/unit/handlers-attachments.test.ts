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

async function createCipher(): Promise<string> {
  const response = await app.fetch(
    jsonRequest(
      '/api/ciphers',
      { type: 2, name: '2.note', secureNote: { type: 0 } },
      'POST',
      token,
    ),
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

describe('attachment creation', () => {
  it('rejects creation when no storage backend is configured', async () => {
    const cipherId = await createCipher();
    const response = await app.fetch(
      jsonRequest(
        `/api/ciphers/${cipherId}/attachment/v2`,
        { key: '2.key', fileName: 'file.bin', fileSize: 5 },
        'POST',
        token,
      ),
      env,
      executionContext,
    );
    expect(response.status).toBe(400);
    expect(await response.json()).toEqual({ error: 'Attachments are not enabled' });
  });

  it('creates a pending attachment with an upload URL', async () => {
    const bucket = new FakeR2Bucket();
    env = { ...env, ATTACHMENTS_BUCKET: bucket } as unknown as Env;
    const cipherId = await createCipher();

    const response = await app.fetch(
      jsonRequest(
        `/api/ciphers/${cipherId}/attachment/v2`,
        { key: '2.key', fileName: 'file.bin', fileSize: 5 },
        'POST',
        token,
      ),
      env,
      executionContext,
    );
    expect(response.status).toBe(200);

    const body = (await response.json()) as Record<string, unknown>;
    expect(body.object).toBe('attachment-fileUpload');
    expect(body.fileUploadType).toBe(1);
    expect(String(body.url)).toContain('/azure-upload?token=');

    const cipherResponse = body.cipherResponse as { attachments: Array<Record<string, unknown>> };
    expect(cipherResponse.attachments).toHaveLength(1);
    expect(cipherResponse.attachments[0]).toMatchObject({
      fileName: 'file.bin',
      size: '5',
      sizeName: '5.00 B',
      object: 'attachment',
    });

    const pending = d1.raw.prepare('SELECT COUNT(*) AS c FROM attachments_pending').get() as {
      c: number;
    };
    expect(pending.c).toBe(1);
  });

  it('rejects a non-positive declared size', async () => {
    env = { ...env, ATTACHMENTS_BUCKET: new FakeR2Bucket() } as unknown as Env;
    const cipherId = await createCipher();

    const response = await app.fetch(
      jsonRequest(
        `/api/ciphers/${cipherId}/attachment/v2`,
        { key: 'k', fileName: 'f', fileSize: 0 },
        'POST',
        token,
      ),
      env,
      executionContext,
    );
    expect(response.status).toBe(400);
    expect(await response.json()).toEqual({ error: 'Attachment size must be positive' });
  });
});

describe('attachment streaming', () => {
  it('uploads, downloads and deletes an attachment', async () => {
    const bucket = new FakeR2Bucket();
    env = { ...env, ATTACHMENTS_BUCKET: bucket } as unknown as Env;
    const cipherId = await createCipher();

    const created = (await (
      await app.fetch(
        jsonRequest(
          `/api/ciphers/${cipherId}/attachment/v2`,
          { key: '2.key', fileName: 'file.bin', fileSize: 5 },
          'POST',
          token,
        ),
        env,
        executionContext,
      )
    ).json()) as { attachmentId: string; url: string };

    const uploadUrl = new URL(created.url);
    const upload = await handleStreaming(
      new Request(uploadUrl, {
        method: 'PUT',
        body: 'hello',
        headers: { 'content-length': '5' },
      }),
      env,
      uploadUrl,
    );
    expect(upload.status).toBe(201);

    const pending = d1.raw.prepare('SELECT COUNT(*) AS c FROM attachments_pending').get() as {
      c: number;
    };
    const committed = d1.raw.prepare('SELECT COUNT(*) AS c FROM attachments').get() as {
      c: number;
    };
    expect(pending.c).toBe(0);
    expect(committed.c).toBe(1);
    expect(bucket.store.get(`${cipherId}/${created.attachmentId}`)).toBeDefined();

    const metadata = (await (
      await app.fetch(
        new Request(
          `https://example.com/api/ciphers/${cipherId}/attachment/${created.attachmentId}`,
          {
            headers: { authorization: `Bearer ${token}` },
          },
        ),
        env,
        executionContext,
      )
    ).json()) as { url: string; size: string; sizeName: string };

    expect(metadata.size).toBe('5');
    expect(metadata.sizeName).toBe('5.00 B');

    const downloadUrl = new URL(metadata.url);
    const download = await handleStreaming(
      new Request(downloadUrl, { method: 'GET' }),
      env,
      downloadUrl,
    );
    expect(download.status).toBe(200);
    expect(download.headers.get('content-disposition')).toBe('attachment');
    expect(download.headers.get('x-content-type-options')).toBe('nosniff');
    expect(await download.text()).toBe('hello');

    const deleted = await app.fetch(
      new Request(
        `https://example.com/api/ciphers/${cipherId}/attachment/${created.attachmentId}`,
        { method: 'DELETE', headers: { authorization: `Bearer ${token}` } },
      ),
      env,
      executionContext,
    );
    expect(deleted.status).toBe(200);
    expect(bucket.store.size).toBe(0);
  });

  it('rejects a size mismatch and removes the stored object', async () => {
    const bucket = new FakeR2Bucket();
    env = { ...env, ATTACHMENTS_BUCKET: bucket } as unknown as Env;
    const cipherId = await createCipher();

    const created = (await (
      await app.fetch(
        jsonRequest(
          `/api/ciphers/${cipherId}/attachment/v2`,
          { key: 'k', fileName: 'f', fileSize: 10 },
          'POST',
          token,
        ),
        env,
        executionContext,
      )
    ).json()) as { url: string };

    const uploadUrl = new URL(created.url);
    const response = await handleStreaming(
      new Request(uploadUrl, {
        method: 'PUT',
        body: 'hello',
        headers: { 'content-length': '5' },
      }),
      env,
      uploadUrl,
    );
    expect(response.status).toBe(400);
    expect(await response.json()).toEqual({
      error: 'Uploaded size (5) does not match declared size (10)',
    });
  });

  it('rejects an invalid token', async () => {
    const bucket = new FakeR2Bucket();
    env = { ...env, ATTACHMENTS_BUCKET: bucket } as unknown as Env;
    const cipherId = await createCipher();

    const url = new URL(
      `https://example.com/api/ciphers/${cipherId}/attachment/missing/download?token=bad`,
    );
    const response = await handleStreaming(new Request(url), env, url);
    expect(response.status).toBe(401);
    expect(await response.json()).toEqual({ error: 'Invalid token' });
  });
});

describe('multipart compatibility endpoints', () => {
  it('accepts a legacy multipart upload', async () => {
    const bucket = new FakeR2Bucket();
    env = { ...env, ATTACHMENTS_BUCKET: bucket } as unknown as Env;
    const cipherId = await createCipher();

    const form = new FormData();
    form.append('data', new File([new Uint8Array([1, 2, 3, 4, 5])], 'f.bin'));
    form.append('key', '2.key');

    const response = await app.fetch(
      new Request(`https://example.com/api/ciphers/${cipherId}/attachment`, {
        method: 'POST',
        headers: { authorization: `Bearer ${token}` },
        body: form,
      }),
      env,
      executionContext,
    );
    expect(response.status).toBe(200);

    const body = (await response.json()) as { attachments: Array<Record<string, unknown>> };
    expect(body.attachments).toHaveLength(1);
    expect(body.attachments[0]).toMatchObject({ fileName: 'f.bin', size: '5', sizeName: '5.00 B' });

    const committed = d1.raw.prepare('SELECT COUNT(*) AS c FROM attachments').get() as {
      c: number;
    };
    expect(committed.c).toBe(1);
    expect(bucket.store.size).toBe(1);
  });

  it('accepts a v2 multipart data upload', async () => {
    const bucket = new FakeR2Bucket();
    env = { ...env, ATTACHMENTS_BUCKET: bucket } as unknown as Env;
    const cipherId = await createCipher();

    const created = (await (
      await app.fetch(
        jsonRequest(
          `/api/ciphers/${cipherId}/attachment/v2`,
          { key: '2.key', fileName: 'f.bin', fileSize: 5 },
          'POST',
          token,
        ),
        env,
        executionContext,
      )
    ).json()) as { attachmentId: string };

    const form = new FormData();
    form.append('data', new File([new Uint8Array([1, 2, 3, 4, 5])], 'f.bin'));

    const response = await app.fetch(
      new Request(
        `https://example.com/api/ciphers/${cipherId}/attachment/${created.attachmentId}`,
        {
          method: 'POST',
          headers: { authorization: `Bearer ${token}` },
          body: form,
        },
      ),
      env,
      executionContext,
    );
    expect(response.status).toBe(200);
    expect(await response.text()).toBe('null');

    const pending = d1.raw.prepare('SELECT COUNT(*) AS c FROM attachments_pending').get() as {
      c: number;
    };
    const committed = d1.raw.prepare('SELECT COUNT(*) AS c FROM attachments').get() as {
      c: number;
    };
    expect(pending.c).toBe(0);
    expect(committed.c).toBe(1);
  });
});
