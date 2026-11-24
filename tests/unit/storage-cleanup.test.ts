import { readFileSync } from 'node:fs';

import { beforeEach, describe, expect, it } from 'vitest';

import { makeApp } from '../../src/app';
import { nowString } from '../../src/db/client';
import type { Env } from '../../src/env';
import { FakeKVNamespace } from '../helpers/fake-storage';
import { createTestD1, type TestD1, testEnv } from '../helpers/sqlite-d1';

/**
 * Regression tests for the storage leaks found on the deployed instance: the
 * hard-delete paths removed database rows but left attachment and Send objects
 * in KV/R2 forever. The reference implementation deletes them (`ciphers.rs`
 * 453/500/957, `accounts.rs` 589).
 */

const schema = readFileSync('sql/schema.sql', 'utf8');
const CLIENT_HASH = 'client-master-password-hash';

const executionContext = {
  waitUntil: () => undefined,
  passThroughOnException: () => undefined,
} as unknown as ExecutionContext;

const app = makeApp();

let d1: TestD1;
let env: Env;
let kv: FakeKVNamespace;

interface Session {
  token: string;
  userId: string;
}

async function registerAndLogin(email: string): Promise<Session> {
  const kdf = { kdfType: 0, iterations: 600000 };
  await app.fetch(
    new Request('https://example.com/identity/accounts/register', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        email,
        name: email,
        masterPasswordHint: null,
        userAsymmetricKeys: { publicKey: 'pk', encryptedPrivateKey: 'epk' },
        masterPasswordAuthentication: { kdf, salt: email, hash: CLIENT_HASH },
        masterPasswordUnlock: { kdf, salt: email, key: 'user-key' },
      }),
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
        username: email,
        password: CLIENT_HASH,
        scope: 'api offline_access',
        client_id: 'cli',
        device_identifier: `device-${email}`,
        device_name: 'Device',
        device_type: '9',
      }).toString(),
    }),
    env,
    executionContext,
  );

  const body = (await response.json()) as { access_token: string };
  const row = d1.raw.prepare('SELECT id FROM users WHERE email = ?').get(email) as { id: string };
  return { token: body.access_token, userId: row.id };
}

function bearer(token: string): Record<string, string> {
  return { authorization: `Bearer ${token}` };
}

async function createCipher(session: Session): Promise<string> {
  const response = await app.fetch(
    new Request('https://example.com/api/ciphers', {
      method: 'POST',
      headers: { 'content-type': 'application/json', ...bearer(session.token) },
      body: JSON.stringify({ type: 2, name: '2.note', secureNote: { type: 0 } }),
    }),
    env,
    executionContext,
  );
  return ((await response.json()) as { id: string }).id;
}

function seedAttachment(cipherId: string, attachmentId: string): string {
  const now = nowString();
  d1.raw
    .prepare(
      `INSERT INTO attachments (id, cipher_id, file_name, file_size, akey, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
    )
    .run(attachmentId, cipherId, 'file.bin', 5, '2.key', now, now);

  const key = `${cipherId}/${attachmentId}`;
  kv.store.set(key, { bytes: new Uint8Array([1, 2, 3, 4, 5]), metadata: {} });
  return key;
}

function seedFileSend(userId: string, sendId: string, fileId: string): string {
  const now = nowString();
  d1.raw
    .prepare(
      `INSERT INTO sends (id, user_id, name, type, data, akey, created_at, updated_at, deletion_date)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    )
    .run(
      sendId,
      userId,
      '2.send',
      1,
      JSON.stringify({ id: fileId, size: '1' }),
      '2.key',
      now,
      now,
      new Date(Date.now() + 86_400_000).toISOString(),
    );

  const key = `sends/${sendId}/${fileId}`;
  kv.store.set(key, { bytes: new Uint8Array([9]), metadata: {} });
  return key;
}

let session: Session;

beforeEach(async () => {
  d1 = createTestD1(schema);
  kv = new FakeKVNamespace();
  env = testEnv(d1, { ATTACHMENTS_KV: kv }) as unknown as Env;
  session = await registerAndLogin('owner@example.com');
});

describe('single cipher hard delete', () => {
  it('removes the attachment object', async () => {
    const cipherId = await createCipher(session);
    const key = seedAttachment(cipherId, 'attachment-1');

    const response = await app.fetch(
      new Request(`https://example.com/api/ciphers/${cipherId}`, {
        method: 'DELETE',
        headers: bearer(session.token),
      }),
      env,
      executionContext,
    );

    expect(response.status).toBe(200);
    expect(kv.store.has(key)).toBe(false);
  });
});

describe('bulk cipher hard delete', () => {
  it('removes every attachment object of the deleted ciphers', async () => {
    const first = await createCipher(session);
    const second = await createCipher(session);
    const keys = [seedAttachment(first, 'a1'), seedAttachment(second, 'a2')];

    const response = await app.fetch(
      new Request('https://example.com/api/ciphers/delete', {
        method: 'POST',
        headers: { 'content-type': 'application/json', ...bearer(session.token) },
        body: JSON.stringify({ ids: [first, second] }),
      }),
      env,
      executionContext,
    );

    expect(response.status).toBe(200);
    for (const key of keys) expect(kv.store.has(key)).toBe(false);
  });

  it('never touches another user objects, even with a crafted id list', async () => {
    const other = await registerAndLogin('other@example.com');
    const otherCipher = await createCipher(other);
    const otherKey = seedAttachment(otherCipher, 'attachment-x');

    const response = await app.fetch(
      new Request('https://example.com/api/ciphers/delete', {
        method: 'POST',
        headers: { 'content-type': 'application/json', ...bearer(session.token) },
        body: JSON.stringify({ ids: [otherCipher] }),
      }),
      env,
      executionContext,
    );

    expect(response.status).toBe(200);
    expect(kv.store.has(otherKey)).toBe(true);

    const row = d1.raw
      .prepare('SELECT COUNT(*) AS c FROM ciphers WHERE id = ?')
      .get(otherCipher) as {
      c: number;
    };
    expect(row.c).toBe(1);
  });
});

describe('vault purge', () => {
  it('removes every attachment object the user owns', async () => {
    const first = await createCipher(session);
    const second = await createCipher(session);
    const keys = [seedAttachment(first, 'a1'), seedAttachment(second, 'a2')];

    const response = await app.fetch(
      new Request('https://example.com/api/ciphers/purge', {
        method: 'POST',
        headers: { 'content-type': 'application/json', ...bearer(session.token) },
        body: JSON.stringify({ masterPasswordHash: CLIENT_HASH }),
      }),
      env,
      executionContext,
    );

    expect(response.status).toBe(200);
    for (const key of keys) expect(kv.store.has(key)).toBe(false);
  });
});

describe('account deletion', () => {
  it('removes attachment and Send objects before dropping the rows', async () => {
    const cipherId = await createCipher(session);
    const attachmentKey = seedAttachment(cipherId, 'attachment-1');
    const sendKey = seedFileSend(session.userId, 'send-1', 'file-1');

    const response = await app.fetch(
      new Request('https://example.com/api/accounts', {
        method: 'DELETE',
        headers: { 'content-type': 'application/json', ...bearer(session.token) },
        body: JSON.stringify({ masterPasswordHash: CLIENT_HASH }),
      }),
      env,
      executionContext,
    );

    expect(response.status).toBe(200);
    expect(kv.store.has(attachmentKey)).toBe(false);
    expect(kv.store.has(sendKey)).toBe(false);

    const users = d1.raw.prepare('SELECT COUNT(*) AS c FROM users').get() as { c: number };
    expect(users.c).toBe(0);
  });
});
