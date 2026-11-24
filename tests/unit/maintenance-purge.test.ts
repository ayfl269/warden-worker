import { readFileSync } from 'node:fs';

import { beforeEach, describe, expect, it } from 'vitest';

import { makeApp } from '../../src/app';
import { nowString } from '../../src/db/client';
import type { Env } from '../../src/env';
import {
  purgeDeletedCiphers,
  purgeExpiredAuthRequests,
  purgeExpiredSends,
  purgeStalePendingAttachments,
  purgeStalePendingSends,
  runScheduledPurges,
  trashAutoDeleteDays,
} from '../../src/maintenance/purge';
import { FakeKVNamespace } from '../helpers/fake-storage';
import { createTestD1, type TestD1, testEnv } from '../helpers/sqlite-d1';

const schema = readFileSync('sql/schema.sql', 'utf8');
const CLIENT_HASH = 'client-master-password-hash';
const EMAIL = 'purge@example.com';

const executionContext = {
  waitUntil: () => undefined,
  passThroughOnException: () => undefined,
} as unknown as ExecutionContext;

const app = makeApp();

let d1: TestD1;
let env: Env;
let kv: FakeKVNamespace;
let token: string;
let userId: string;

function daysAgo(days: number): string {
  return new Date(Date.now() - days * 86_400_000).toISOString();
}

function minutesAgo(minutes: number): string {
  return new Date(Date.now() - minutes * 60_000).toISOString();
}

async function registerAndLogin(): Promise<{ token: string; userId: string }> {
  const kdf = { kdfType: 0, iterations: 600000 };
  await app.fetch(
    new Request('https://example.com/identity/accounts/register', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        email: EMAIL,
        name: 'Purge',
        masterPasswordHint: null,
        userAsymmetricKeys: { publicKey: 'pk', encryptedPrivateKey: 'epk' },
        masterPasswordAuthentication: { kdf, salt: EMAIL, hash: CLIENT_HASH },
        masterPasswordUnlock: { kdf, salt: EMAIL, key: 'user-key' },
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

  const body = (await response.json()) as { access_token: string };
  const row = d1.raw.prepare('SELECT id FROM users WHERE email = ?').get(EMAIL) as { id: string };
  return { token: body.access_token, userId: row.id };
}

async function createCipher(): Promise<string> {
  const response = await app.fetch(
    new Request('https://example.com/api/ciphers', {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: `Bearer ${token}` },
      body: JSON.stringify({ type: 2, name: '2.note', secureNote: { type: 0 } }),
    }),
    env,
    executionContext,
  );
  return ((await response.json()) as { id: string }).id;
}

/** Seed an attachment row plus its storage object. */
function seedAttachment(cipherId: string, attachmentId: string): void {
  const now = nowString();
  d1.raw
    .prepare(
      `INSERT INTO attachments (id, cipher_id, file_name, file_size, akey, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
    )
    .run(attachmentId, cipherId, 'file.bin', 5, '2.key', now, now);
  kv.store.set(`${cipherId}/${attachmentId}`, {
    bytes: new Uint8Array([1, 2, 3, 4, 5]),
    metadata: {},
  });
}

function seedSend(id: string, fileId: string, deletionDate: string): void {
  const now = nowString();
  d1.raw
    .prepare(
      `INSERT INTO sends (id, user_id, name, type, data, akey, created_at, updated_at, deletion_date)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    )
    .run(
      id,
      userId,
      '2.send',
      1,
      JSON.stringify({ id: fileId, size: '5', fileName: 'f.bin' }),
      '2.key',
      now,
      now,
      deletionDate,
    );
  kv.store.set(`sends/${id}/${fileId}`, { bytes: new Uint8Array([9]), metadata: {} });
}

beforeEach(async () => {
  d1 = createTestD1(schema);
  kv = new FakeKVNamespace();
  env = testEnv(d1, { ATTACHMENTS_KV: kv }) as unknown as Env;
  ({ token, userId } = await registerAndLogin());
});

describe('trashAutoDeleteDays', () => {
  it('defaults to 30 and accepts any integer, like the reference implementation', () => {
    expect(trashAutoDeleteDays(env)).toBe(30);
    expect(trashAutoDeleteDays({ ...env, TRASH_AUTO_DELETE_DAYS: '7' } as Env)).toBe(7);
    expect(trashAutoDeleteDays({ ...env, TRASH_AUTO_DELETE_DAYS: '0' } as Env)).toBe(0);
    expect(trashAutoDeleteDays({ ...env, TRASH_AUTO_DELETE_DAYS: '-5' } as Env)).toBe(-5);
    expect(trashAutoDeleteDays({ ...env, TRASH_AUTO_DELETE_DAYS: 'soon' } as Env)).toBe(30);
  });
});

describe('purgeStalePendingAttachments', () => {
  it('drops uploads older than a day and keeps fresh ones', async () => {
    const cipherId = await createCipher();
    const insert = d1.raw.prepare(
      `INSERT INTO attachments_pending (id, cipher_id, file_name, file_size, akey, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
    );
    insert.run('old', cipherId, 'old.bin', 5, 'k', daysAgo(2), daysAgo(2));
    insert.run('fresh', cipherId, 'fresh.bin', 5, 'k', nowString(), nowString());

    expect(await purgeStalePendingAttachments(env)).toBe(1);

    const rows = d1.raw.prepare('SELECT id FROM attachments_pending').all() as { id: string }[];
    expect(rows.map((row) => row.id)).toEqual(['fresh']);
  });
});

describe('purgeDeletedCiphers', () => {
  it('deletes trashed ciphers past the retention window and their storage objects', async () => {
    const cipherId = await createCipher();
    seedAttachment(cipherId, 'attachment-1');
    d1.raw.prepare('UPDATE ciphers SET deleted_at = ? WHERE id = ?').run(daysAgo(31), cipherId);

    expect(await purgeDeletedCiphers(env)).toBe(1);

    const ciphers = d1.raw.prepare('SELECT COUNT(*) AS c FROM ciphers').get() as { c: number };
    expect(ciphers.c).toBe(0);
    expect(kv.store.has(`${cipherId}/attachment-1`)).toBe(false);
  });

  it('bumps the owner revision date so clients resync', async () => {
    const cipherId = await createCipher();
    d1.raw
      .prepare('UPDATE users SET updated_at = ? WHERE id = ?')
      .run('2000-01-01T00:00:00.000Z', userId);
    d1.raw.prepare('UPDATE ciphers SET deleted_at = ? WHERE id = ?').run(daysAgo(31), cipherId);

    await purgeDeletedCiphers(env);

    const user = d1.raw.prepare('SELECT updated_at FROM users WHERE id = ?').get(userId) as {
      updated_at: string;
    };
    expect(user.updated_at).not.toBe('2000-01-01T00:00:00.000Z');
  });

  it('keeps recently trashed ciphers', async () => {
    const cipherId = await createCipher();
    seedAttachment(cipherId, 'attachment-1');
    d1.raw.prepare('UPDATE ciphers SET deleted_at = ? WHERE id = ?').run(daysAgo(1), cipherId);

    expect(await purgeDeletedCiphers(env)).toBe(0);
    expect(kv.store.has(`${cipherId}/attachment-1`)).toBe(true);
  });

  it('is disabled when TRASH_AUTO_DELETE_DAYS is zero or negative', async () => {
    const cipherId = await createCipher();
    d1.raw.prepare('UPDATE ciphers SET deleted_at = ? WHERE id = ?').run(daysAgo(31), cipherId);

    const disabled = { ...env, TRASH_AUTO_DELETE_DAYS: '0' } as Env;
    expect(await purgeDeletedCiphers(disabled)).toBe(0);

    const ciphers = d1.raw.prepare('SELECT COUNT(*) AS c FROM ciphers').get() as { c: number };
    expect(ciphers.c).toBe(1);
  });
});

describe('purgeStalePendingSends', () => {
  it('drops unfinished uploads and their objects', async () => {
    const now = nowString();
    d1.raw
      .prepare(
        `INSERT INTO sends_pending (id, user_id, name, type, data, akey, created_at, updated_at, deletion_date)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        'pending-1',
        userId,
        '2.send',
        1,
        JSON.stringify({ id: 'file-1', size: '1' }),
        '2.key',
        daysAgo(2),
        daysAgo(2),
        daysAgo(1),
      );
    kv.store.set('sends/pending-1/file-1', { bytes: new Uint8Array([1]), metadata: {} });

    expect(await purgeStalePendingSends(env)).toBe(1);

    expect(kv.store.has('sends/pending-1/file-1')).toBe(false);
    const rows = d1.raw.prepare('SELECT COUNT(*) AS c FROM sends_pending').get() as { c: number };
    expect(rows.c).toBe(0);
  });
});

describe('purgeExpiredSends', () => {
  it('deletes sends past their deletion date and their file objects', async () => {
    seedSend('send-expired', 'file-1', daysAgo(1));
    seedSend('send-live', 'file-2', new Date(Date.now() + 86_400_000).toISOString());

    expect(await purgeExpiredSends(env)).toBe(1);

    expect(kv.store.has('sends/send-expired/file-1')).toBe(false);
    expect(kv.store.has('sends/send-live/file-2')).toBe(true);

    const rows = d1.raw.prepare('SELECT id FROM sends').all() as { id: string }[];
    expect(rows.map((row) => row.id)).toEqual(['send-live']);
  });
});

describe('purgeExpiredAuthRequests', () => {
  it('deletes auth requests older than 15 minutes', async () => {
    const insert = d1.raw.prepare(
      `INSERT INTO auth_requests
         (id, user_id, request_device_identifier, device_type, request_ip, access_code, public_key, creation_date)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    );
    insert.run('old', userId, 'device-x', 9, '1.2.3.4', 'code', 'pk', minutesAgo(20));
    insert.run('fresh', userId, 'device-y', 9, '1.2.3.4', 'code', 'pk', nowString());

    expect(await purgeExpiredAuthRequests(env)).toBe(1);

    const rows = d1.raw.prepare('SELECT id FROM auth_requests').all() as { id: string }[];
    expect(rows.map((row) => row.id)).toEqual(['fresh']);
  });
});

describe('runScheduledPurges', () => {
  it('runs every task and reports each count', async () => {
    const cipherId = await createCipher();
    seedAttachment(cipherId, 'attachment-1');
    d1.raw.prepare('UPDATE ciphers SET deleted_at = ? WHERE id = ?').run(daysAgo(31), cipherId);
    seedSend('send-expired', 'file-1', daysAgo(1));

    const report = await runScheduledPurges(env);

    expect(report).toEqual({
      pendingAttachments: 0,
      deletedCiphers: 1,
      stalePendingSends: 0,
      expiredSends: 1,
      expiredAuthRequests: 0,
    });
  });

  it('works without a storage backend configured', async () => {
    const noStorage = testEnv(d1) as unknown as Env;
    const cipherId = await createCipher();
    d1.raw.prepare('UPDATE ciphers SET deleted_at = ? WHERE id = ?').run(daysAgo(31), cipherId);

    await expect(runScheduledPurges(noStorage)).resolves.toMatchObject({ deletedCiphers: 1 });
  });
});
