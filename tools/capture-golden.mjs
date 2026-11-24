#!/usr/bin/env node
/**
 * Capture golden HTTP fixtures from the current Rust implementation.
 *
 * MUST be run before the Rust code is deleted. Requires a locally running
 * reference worker:
 *
 *   # .dev.vars (or exported env) needs at least:
 *   #   JWT_SECRET=dev-secret
 *   #   JWT_REFRESH_SECRET=dev-refresh-secret
 *   #   ALLOWED_EMAILS=*@example.com
 *   wrangler dev --local --persist-to .wrangler/state
 *
 *   BASE_URL=http://127.0.0.1:8787 node tools/capture-golden.mjs
 *
 * Output: tests/golden/http.json — one entry per call, with volatile values
 * (ids, timestamps, JWTs, tokens) normalized so the TypeScript implementation
 * can be diffed against it.
 *
 * The script is intentionally tolerant: a case that fails still gets recorded,
 * because error responses are part of the contract too.
 */

import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';

const BASE_URL = process.env.BASE_URL ?? 'http://127.0.0.1:8787';
const OUT_PATH = process.env.GOLDEN_OUT ?? 'tests/golden/http.json';

/** Deterministic fake client-side master password hash (base64 of 32 zero bytes). */
const CLIENT_HASH = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=';
/**
 * Capture against an existing account instead of registering one:
 *   GOLDEN_EMAIL=you@example.com GOLDEN_PASSWORD_HASH=<client-side master password hash>
 * Destructive flows (session revocation, account deletion) stay disabled unless
 * GOLDEN_DESTRUCTIVE=1 is set.
 */
const EMAIL = process.env.GOLDEN_EMAIL ?? `golden-${Date.now()}@example.com`;
const PASSWORD =
  process.env.GOLDEN_PASSWORD_HASH ??
  (process.env.GOLDEN_PASSWORD_HASH_FILE !== undefined
    ? readFileSync(process.env.GOLDEN_PASSWORD_HASH_FILE, 'utf8').trim()
    : CLIENT_HASH);
/** `GOLDEN_REGISTER=1` forces registration even when GOLDEN_EMAIL is set. */
const EXISTING_ACCOUNT =
  process.env.GOLDEN_REGISTER !== '1' && process.env.GOLDEN_EMAIL !== undefined;
const DESTRUCTIVE = process.env.GOLDEN_DESTRUCTIVE === '1';
const KDF = { kdfType: 0, iterations: 600_000 };

const cases = [];
const state = {};

// ── normalization ───────────────────────────────────────────────────

const UUID_RE = /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi;
const ISO_RE = /\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z/g;
const JWT_RE = /eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g;
const OPAQUE_KEYS = new Set([
  'access_token',
  'refresh_token',
  'TwoFactorToken',
  'token',
  // Never persist the client-side master password hash.
  'password',
  'password_hash_b64',
  'masterPasswordHash',
  'newMasterPasswordHash',
]);

function normalizeString(value, key) {
  let out = value;
  if (OPAQUE_KEYS.has(key)) return '<opaque>';
  if (key === 'url') out = out.replace(/([?&](?:token|t)=)[^&]+/g, '$1<opaque>');
  out = out.replace(JWT_RE, '<jwt>');
  out = out.replace(ISO_RE, '<ts>');
  out = out.replace(UUID_RE, '<uuid>');
  if (out === EMAIL) return '<email>';
  return out;
}

function normalize(value, key = '') {
  if (typeof value === 'string') return normalizeString(value, key);
  if (Array.isArray(value)) return value.map((item) => normalize(item, key));
  if (value !== null && typeof value === 'object') {
    const out = {};
    for (const [childKey, childValue] of Object.entries(value)) {
      out[childKey] = normalize(childValue, childKey);
    }
    return out;
  }
  return value;
}

// ── HTTP helper ─────────────────────────────────────────────────────

function splitPath(path) {
  const index = path.indexOf('?');
  return index === -1 ? [path, ''] : [path.slice(0, index), path.slice(index)];
}

async function call(name, { method = 'GET', path, body, form, token, omitBody = false } = {}) {
  const headers = {};
  let payload;

  if (body !== undefined) {
    headers['content-type'] = 'application/json';
    payload = JSON.stringify(body);
  } else if (form !== undefined) {
    headers['content-type'] = 'application/x-www-form-urlencoded';
    payload = new URLSearchParams(form).toString();
  }
  if (token !== undefined) headers.authorization = `Bearer ${token}`;

  let status = 0;
  let contentType = null;
  let parsed = null;

  try {
    const response = await fetch(new URL(path, BASE_URL), {
      method,
      headers,
      body: payload,
    });
    status = response.status;
    contentType = response.headers.get('content-type');
    const text = await response.text();
    try {
      parsed = JSON.parse(text);
    } catch {
      parsed = text;
    }
  } catch (error) {
    parsed = { transportError: String(error) };
  }

  const [pathname, query] = splitPath(path);
  const recordBody =
    payload === undefined || omitBody
      ? null
      : body !== undefined
        ? normalize(body)
        : Object.fromEntries(new URLSearchParams(payload));

  cases.push({
    name,
    request: {
      method,
      path: pathname,
      query: query.length > 0 ? normalize(query) : '',
      hasBody: payload !== undefined && !omitBody,
      body: recordBody,
    },
    response: {
      status,
      contentType,
      body: normalize(parsed),
    },
  });

  return { status, body: parsed };
}

// ── flows ───────────────────────────────────────────────────────────

async function main() {
  console.log(`Capturing against ${BASE_URL}`);

  // Meta / config
  await call('config', { path: '/api/config' });
  await call('version', { path: '/api/version' });
  await call('now', { path: '/api/now' });
  await call('hibp', { path: '/api/hibp/breach?username=test' });
  await call('alive', { path: '/api/alive' });
  await call('unknown-route', { path: '/api/does-not-exist' });
  await call('wrong-method', { method: 'POST', path: '/api/config' });

  // Registration (current 2026.5.0+ format)
  await call('prelogin-missing-user', {
    method: 'POST',
    path: '/identity/accounts/prelogin',
    body: { email: EMAIL },
  });
  if (!EXISTING_ACCOUNT) {
    await call('register-current', {
      method: 'POST',
      path: '/identity/accounts/register',
      body: {
        email: EMAIL,
        name: 'Golden',
        masterPasswordHint: null,
        userAsymmetricKeys: {
          publicKey: 'golden-public-key',
          encryptedPrivateKey: 'golden-encrypted-private-key',
        },
        masterPasswordAuthentication: { kdf: KDF, salt: EMAIL.toLowerCase(), hash: CLIENT_HASH },
        masterPasswordUnlock: { kdf: KDF, salt: EMAIL.toLowerCase(), key: 'golden-user-key' },
      },
    });
  }

  // Login
  const login = await call('token-password', {
    method: 'POST',
    path: '/identity/connect/token',
    form: {
      grant_type: 'password',
      username: EMAIL,
      password: PASSWORD,
      scope: 'api offline_access',
      client_id: 'cli',
      deviceType: '9',
      deviceIdentifier: 'golden-device',
      deviceName: 'Golden Device',
    },
  });

  const accessToken = login.body?.access_token;
  const refreshToken = login.body?.refresh_token;
  state.accessToken = accessToken;

  if (typeof accessToken !== 'string' || accessToken.length === 0) {
    throw new Error(
      `login failed (${login.status}); refusing to record unauthenticated noise. ` +
        `Check GOLDEN_EMAIL / GOLDEN_PASSWORD_HASH. Response: ${JSON.stringify(login.body)}`,
    );
  }

  // Authenticated basics
  await call('sync-empty', { path: '/api/sync', token: accessToken });
  await call('profile', { path: '/api/accounts/profile', token: accessToken });
  await call('revision-date', { path: '/api/accounts/revision-date', token: accessToken });
  await call('two-factor-list', { path: '/api/two-factor', token: accessToken });

  // Folders
  const folder = await call('folder-create', {
    method: 'POST',
    path: '/api/folders',
    token: accessToken,
    body: { name: '2.golden-folder-name' },
  });
  const folderId = folder.body?.id;
  await call('folder-list', { path: '/api/folders', token: accessToken });
  if (folderId !== undefined) {
    await call('folder-get', { path: `/api/folders/${folderId}`, token: accessToken });
  }

  // Ciphers
  const cipher = await call('cipher-create', {
    method: 'POST',
    path: '/api/ciphers',
    token: accessToken,
    body: {
      type: 2,
      name: '2.golden-note',
      notes: null,
      folderId: folderId ?? null,
      favorite: false,
      secureNote: { type: 0 },
    },
  });
  const cipherId = cipher.body?.id;

  await call('cipher-list', { path: '/api/ciphers', token: accessToken });
  if (cipherId !== undefined) {
    await call('cipher-get', { path: `/api/ciphers/${cipherId}`, token: accessToken });
    await call('cipher-partial-favorite', {
      method: 'PUT',
      path: `/api/ciphers/${cipherId}/partial`,
      token: accessToken,
      body: { favorite: true },
    });
    await call('cipher-update', {
      method: 'PUT',
      path: `/api/ciphers/${cipherId}`,
      token: accessToken,
      body: {
        type: 2,
        name: '2.golden-note-updated',
        notes: '2.notes',
        folderId: folderId ?? null,
        favorite: true,
        secureNote: { type: 0 },
      },
    });
    await call('sync-with-cipher', { path: '/api/sync', token: accessToken });
    await call('cipher-soft-delete', {
      method: 'PUT',
      path: `/api/ciphers/${cipherId}/delete`,
      token: accessToken,
    });
    await call('cipher-restore', {
      method: 'PUT',
      path: `/api/ciphers/${cipherId}/restore`,
      token: accessToken,
    });
    await call('cipher-archive', {
      method: 'PUT',
      path: `/api/ciphers/${cipherId}/archive`,
      token: accessToken,
    });
    await call('cipher-unarchive', {
      method: 'PUT',
      path: `/api/ciphers/${cipherId}/unarchive`,
      token: accessToken,
    });
    await call('cipher-hard-delete', {
      method: 'DELETE',
      path: `/api/ciphers/${cipherId}`,
      token: accessToken,
    });
    await call('cipher-get-deleted', { path: `/api/ciphers/${cipherId}`, token: accessToken });
  }

  // Send (text)
  const send = await call('send-create-text', {
    method: 'POST',
    path: '/api/sends',
    token: accessToken,
    body: {
      type: 0,
      name: '2.golden-send',
      notes: null,
      key: '2.golden-send-key',
      text: { text: '2.golden-send-text', hidden: false },
      file: null,
      maxAccessCount: null,
      deletionDate: new Date(Date.now() + 7 * 24 * 3600 * 1000).toISOString(),
      expirationDate: null,
      disabled: false,
      hideEmail: false,
      password: null,
    },
  });
  const sendId = send.body?.id;
  await call('send-list', { path: '/api/sends', token: accessToken });
  if (sendId !== undefined) {
    await call('send-get', { path: `/api/sends/${sendId}`, token: accessToken });
  }

  // Error contracts
  await call('cipher-get-missing', {
    path: '/api/ciphers/00000000-0000-4000-8000-000000000000',
    token: accessToken,
  });
  await call('unauthenticated', { path: '/api/sync' });
  await call('bad-token', { path: '/api/sync', token: 'not-a-jwt' });

  // Refresh grant
  if (refreshToken !== undefined) {
    await call('token-refresh', {
      method: 'POST',
      path: '/identity/connect/token',
      form: {
        grant_type: 'refresh_token',
        refresh_token: refreshToken,
        client_id: 'cli',
        deviceIdentifier: 'golden-device',
        deviceName: 'Golden Device',
        deviceType: '9',
      },
    });
  }

  // Cleanup: remove only the objects this run created. The account is never
  // touched here, so capturing against a real instance leaves no residue.
  if (sendId !== undefined) {
    await call('send-delete-cleanup', {
      method: 'DELETE',
      path: `/api/sends/${sendId}`,
      token: accessToken,
    });
  }
  if (folderId !== undefined) {
    await call('folder-delete-cleanup', {
      method: 'DELETE',
      path: `/api/folders/${folderId}`,
      token: accessToken,
    });
  }

  // Session revocation and account deletion are destructive: opt-in only.
  if (DESTRUCTIVE) {
    await call('security-stamp', {
      method: 'POST',
      path: '/api/accounts/security-stamp',
      token: accessToken,
      body: { masterPasswordHash: PASSWORD },
    });
    await call('sync-after-logout-all', { path: '/api/sync', token: accessToken });

    const relogin = await call('token-password-relogin', {
      method: 'POST',
      path: '/identity/connect/token',
      form: {
        grant_type: 'password',
        username: EMAIL,
        password: PASSWORD,
        scope: 'api offline_access',
        client_id: 'cli',
        deviceType: '9',
        deviceIdentifier: 'golden-device',
        deviceName: 'Golden Device',
      },
    });

    await call('account-delete', {
      method: 'DELETE',
      path: '/api/accounts',
      token: relogin.body?.access_token,
      body: { masterPasswordHash: PASSWORD },
    });
  }

  // ── write fixtures ────────────────────────────────────────────────
  const payload = {
    baseUrl: BASE_URL,
    capturedAt: new Date().toISOString(),
    note: 'Captured from the Rust reference implementation. Volatile values are normalized.',
    cases,
  };

  mkdirSync(dirname(OUT_PATH), { recursive: true });
  writeFileSync(OUT_PATH, `${JSON.stringify(payload, null, 2)}\n`, 'utf8');

  const failed = cases.filter(
    (entry) => entry.response.status === 0 || entry.response.status >= 500,
  );
  console.log(`Wrote ${cases.length} cases to ${OUT_PATH}`);
  if (failed.length > 0) {
    console.warn(`⚠️  ${failed.length} case(s) failed with transport/5xx errors:`);
    for (const entry of failed) {
      console.warn(`   - ${entry.name}: ${entry.response.status}`);
    }
    process.exitCode = 1;
  }
}

main().catch((error) => {
  console.error('Capture aborted:', error);
  process.exitCode = 1;
});
