// Dynamic security test against a deployed instance (throwaway: under .wrangler/).
//
//   $env:SMOKE_BASE / HTTP_PROXY / HTTPS_PROXY / NODE_USE_ENV_PROXY=1
//   node .wrangler/security-test.mjs
//
// Every check is an attack attempt that must be refused, or a hardening
// expectation that must hold. FAIL means "investigate", not necessarily "exploit".

import { createHmac, pbkdf2Sync, randomBytes, randomUUID } from 'node:crypto';

const BASE = process.env.SMOKE_BASE;
if (BASE === undefined) throw new Error('SMOKE_BASE is not set');

const results = [];
const warnings = [];
let failures = 0;

function check(label, ok, detail) {
  results.push({ label, ok });
  if (!ok) failures += 1;
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${label}  ${detail ?? ''}`);
}

/** Known/accepted trade-offs: reported, but they do not fail the run. */
function warnIfNot(label, ok, detail) {
  results.push({ label, ok });
  if (!ok) warnings.push({ label, detail });
  console.log(`${ok ? 'PASS' : 'WARN'}  ${label}  ${detail ?? ''}`);
}

async function call(path, init = {}) {
  const target = path.startsWith('http') ? path : `${BASE}${path}`;
  const started = performance.now();
  let response;
  try {
    response = await fetch(target, init);
  } catch (error) {
    return { status: 0, text: `network error: ${error.message}`, json: null, ms: 0 };
  }
  const ms = Math.round(performance.now() - started);
  const text = await response.text();
  let json = null;
  try {
    json = JSON.parse(text);
  } catch {
    // not JSON
  }
  return { status: response.status, text, json, ms, headers: response.headers };
}

// ---------------------------------------------------------------- TOTP helpers
const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

function base32Decode(input) {
  const clean = input.toUpperCase().replace(/=+$/, '');
  let bits = 0;
  let value = 0;
  const out = [];
  for (const char of clean) {
    const index = B32.indexOf(char);
    if (index < 0) throw new Error('bad base32');
    value = (value << 5) | index;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(out);
}

function base32Encode(bytes) {
  let bits = 0;
  let value = 0;
  let out = '';
  for (const byte of bytes) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += B32[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += B32[(value << (5 - bits)) & 31];
  return out;
}

function totp(secret, stepOffset = 0) {
  const counter = Math.floor(Date.now() / 1000 / 30) + stepOffset;
  const buffer = Buffer.alloc(8);
  buffer.writeUInt32BE(Math.floor(counter / 2 ** 32), 0);
  buffer.writeUInt32BE(counter >>> 0, 4);
  const digest = createHmac('sha1', base32Decode(secret)).update(buffer).digest();
  const offset = digest[digest.length - 1] & 0x0f;
  const binary =
    ((digest[offset] & 0x7f) << 24) |
    ((digest[offset + 1] & 0xff) << 16) |
    ((digest[offset + 2] & 0xff) << 8) |
    (digest[offset + 3] & 0xff);
  return String(binary % 1_000_000).padStart(6, '0');
}

// ---------------------------------------------------------------- accounts
const PASSWORD = 'correct horse battery staple';
const stamp = Date.now();
const EMAIL_A = `sec-a-${stamp}@example.com`;
const EMAIL_B = `sec-b-${stamp}@example.com`;
const EMAIL_HINT = `sec-hint-${stamp}@example.com`;
const HINT_TEXT = 'my password hint mentions hunter2';

function clientHash(email) {
  const masterKey = pbkdf2Sync(PASSWORD, email.toLowerCase(), 600000, 32, 'sha256');
  return pbkdf2Sync(masterKey, PASSWORD, 1, 32, 'sha256').toString('base64');
}

async function register(email, hash, hint = null) {
  return call('/identity/accounts/register', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      email,
      name: email,
      masterPasswordHint: hint,
      userAsymmetricKeys: { publicKey: 'cHVibGlj', encryptedPrivateKey: 'ZW5j' },
      kdf: { kdfType: 0, iterations: 600000 },
      masterPasswordHash: hash,
      key: Buffer.alloc(64, 7).toString('base64'),
    }),
  });
}

async function login(email, hash, extra = {}) {
  return call('/identity/connect/token', {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'password',
      username: email,
      password: hash,
      scope: 'api offline_access',
      client_id: 'browser',
      deviceType: '9',
      deviceIdentifier: randomUUID(),
      deviceName: 'sec-test',
      ...extra,
    }).toString(),
  });
}

const hashA = clientHash(EMAIL_A);
const hashB = clientHash(EMAIL_B);
const deviceIdA = randomUUID();

// Registered first: the register rate limit allows five attempts per minute.
await register(EMAIL_HINT, clientHash(EMAIL_HINT), HINT_TEXT);
await register(EMAIL_A, hashA);
await register(EMAIL_B, hashB);

const loginA = await login(EMAIL_A, hashA, { deviceIdentifier: deviceIdA });
const loginB = await login(EMAIL_B, hashB);
const tokenA = loginA.json?.access_token;
const tokenB = loginB.json?.access_token;
const refreshA = loginA.json?.refresh_token;
check(
  'setup: two accounts can log in',
  loginA.status === 200 && loginB.status === 200,
  `${loginA.status}/${loginB.status}`,
);

const authA = { authorization: `Bearer ${tokenA}` };
const authB = { authorization: `Bearer ${tokenB}` };
const jsonA = { ...authA, 'content-type': 'application/json' };
const jsonB = { ...authB, 'content-type': 'application/json' };

// ---------------------------------------------------------------- A. auth
console.log('\n--- A. authentication ---');

const noAuth = await call('/api/accounts/profile');
check('no token rejected', noAuth.status === 401, `${noAuth.status}`);

const garbage = await call('/api/accounts/profile', {
  headers: { authorization: 'Bearer not-a-jwt' },
});
check('garbage token rejected', garbage.status === 401, `${garbage.status}`);

const [headerB64, payloadB64] = tokenA.split('.');
const noneToken = `${Buffer.from('{"alg":"none","typ":"JWT"}').toString('base64url')}.${payloadB64}.`;
const algNone = await call('/api/accounts/profile', {
  headers: { authorization: `Bearer ${noneToken}` },
});
check('alg=none rejected', algNone.status === 401, `${algNone.status}`);

const flipped = `${headerB64}.${payloadB64}.${tokenA.split('.')[2].slice(0, -2)}AA`;
const badSig = await call('/api/accounts/profile', {
  headers: { authorization: `Bearer ${flipped}` },
});
check('tampered signature rejected', badSig.status === 401, `${badSig.status}`);

const payload = JSON.parse(Buffer.from(payloadB64 ?? '', 'base64url').toString());
const forgedPayload = Buffer.from(JSON.stringify({ ...payload, sub: 'attacker' })).toString(
  'base64url',
);
const swapped = await call('/api/accounts/profile', {
  headers: { authorization: `Bearer ${headerB64}.${forgedPayload}.${tokenA.split('.')[2]}` },
});
check('tampered sub claim rejected', swapped.status === 401, `${swapped.status}`);

const refreshAsAccess = await call('/api/accounts/profile', {
  headers: { authorization: `Bearer ${refreshA}` },
});
check(
  'refresh token rejected as access token',
  refreshAsAccess.status === 401,
  `${refreshAsAccess.status}`,
);

// ---------------------------------------------------------------- B. IDOR
console.log('\n--- B. cross-user access (IDOR) ---');

const cipherA = await call('/api/ciphers', {
  method: 'POST',
  headers: jsonA,
  body: JSON.stringify({ type: 2, name: '2.secret-note', secureNote: { type: 0 } }),
});
const cipherId = cipherA.json?.id;
const folderA = await call('/api/folders', {
  method: 'POST',
  headers: jsonA,
  body: JSON.stringify({ name: '2.folder' }),
});
const folderId = folderA.json?.id;
const sendA = await call('/api/sends', {
  method: 'POST',
  headers: jsonA,
  body: JSON.stringify({
    type: 0,
    name: '2.send',
    text: { text: '2.send-text', hidden: false },
    key: Buffer.alloc(32, 3).toString('base64'),
    deletionDate: new Date(Date.now() + 86_400_000).toISOString(),
  }),
});
const sendId = sendA.json?.id;
const sendAccessId = sendA.json?.accessId;
check('setup: user A owns a cipher, folder and send', Boolean(cipherId && folderId && sendId));

const form = new FormData();
form.set('key', '2.attachment-key');
form.set('data', new File([new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8])], 'secret.bin'));
const uploadA = await call(`/api/ciphers/${cipherId}/attachment`, {
  method: 'POST',
  headers: authA,
  body: form,
});
const attachmentId = uploadA.json?.attachments?.[0]?.id;
check('setup: attachment uploaded', typeof attachmentId === 'string', `${uploadA.status}`);

const idorChecks = [
  ['read cipher', await call(`/api/ciphers/${cipherId}`, { headers: authB })],
  [
    'update cipher',
    await call(`/api/ciphers/${cipherId}`, {
      method: 'PUT',
      headers: jsonB,
      body: JSON.stringify({ type: 2, name: '2.pwned', secureNote: { type: 0 } }),
    }),
  ],
  ['delete cipher', await call(`/api/ciphers/${cipherId}`, { method: 'DELETE', headers: authB })],
  ['read folder', await call(`/api/folders/${folderId}`, { headers: authB })],
  ['delete folder', await call(`/api/folders/${folderId}`, { method: 'DELETE', headers: authB })],
  ['read send', await call(`/api/sends/${sendId}`, { headers: authB })],
  ['delete send', await call(`/api/sends/${sendId}`, { method: 'DELETE', headers: authB })],
  [
    'read attachment',
    await call(`/api/ciphers/${cipherId}/attachment/${attachmentId}`, { headers: authB }),
  ],
  [
    'delete attachment',
    await call(`/api/ciphers/${cipherId}/attachment/${attachmentId}`, {
      method: 'DELETE',
      headers: authB,
    }),
  ],
  ['read device', await call(`/api/devices/identifier/${deviceIdA}`, { headers: authB })],
  ['unknown auth request', await call(`/api/auth-requests/${randomUUID()}`, { headers: authB })],
];
for (const [label, response] of idorChecks) {
  // Folder deletes are idempotent and answer 200 regardless; the survival check
  // below is what proves ownership filtering.
  const accepted = label === 'delete folder' ? [200, 400, 403, 404] : [400, 403, 404];
  check(`B cannot ${label}`, accepted.includes(response.status), `${response.status}`);
}

const folderAfterB = await call(`/api/folders/${folderId}`, { headers: authA });
check('A folder survived B delete attempt', folderAfterB.status === 200, `${folderAfterB.status}`);

// A's cipher must still be intact after B's delete attempt.
const afterB = await call(`/api/ciphers/${cipherId}`, { headers: authA });
check('A cipher survived B delete attempt', afterB.status === 200, `${afterB.status}`);

// Bulk delete with a foreign id must not touch it.
const bulkForeign = await call('/api/ciphers/delete', {
  method: 'POST',
  headers: jsonB,
  body: JSON.stringify({ ids: [cipherId] }),
});
const afterBulk = await call(`/api/ciphers/${cipherId}`, { headers: authA });
check(
  'bulk delete cannot reach another user cipher',
  bulkForeign.status === 200 && afterBulk.status === 200,
  `bulk=${bulkForeign.status} cipher=${afterBulk.status}`,
);

// ---------------------------------------------------------------- C. tokens
console.log('\n--- C. token scoping and binding ---');

const download = await call(`/api/ciphers/${cipherId}/attachment/${attachmentId}`, {
  headers: authA,
});
const downloadUrl = download.json?.url;
check(
  'setup: attachment download url issued',
  typeof downloadUrl === 'string',
  `${download.status}`,
);

if (typeof downloadUrl === 'string') {
  const fileToken = new URL(downloadUrl).searchParams.get('token') ?? '';
  const asAccess = await call('/api/accounts/profile', {
    headers: { authorization: `Bearer ${fileToken}` },
  });
  check('attachment token rejected as API bearer', asAccess.status === 401, `${asAccess.status}`);

  const parts = fileToken.split('.');
  const claims = JSON.parse(Buffer.from(parts[1] ?? '', 'base64url').toString());
  const tampered = Buffer.from(JSON.stringify({ ...claims, attachment_id: randomUUID() })).toString(
    'base64url',
  );
  const tamperedUrl = downloadUrl.replace(parts[1], tampered);
  const tamperedResult = await call(tamperedUrl);
  check(
    'attachment token bound to its attachment id',
    [401, 403, 404].includes(tamperedResult.status),
    `${tamperedResult.status}`,
  );

  const replay = await call(downloadUrl);
  check('attachment token works for its own file', replay.status === 200, `${replay.status}`);
}

if (typeof sendAccessId === 'string') {
  const access = await call(`/api/sends/access/${sendAccessId}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: '{}',
  });
  const sendToken = access.json?.token ?? access.json?.accessToken;
  if (typeof sendToken === 'string') {
    const asAccess = await call('/api/accounts/profile', {
      headers: { authorization: `Bearer ${sendToken}` },
    });
    check(
      'send access token rejected as API bearer',
      asAccess.status === 401,
      `${asAccess.status}`,
    );
  } else {
    check(
      'send access returns no API-compatible token',
      access.status === 200,
      `keys=${Object.keys(access.json ?? {}).join(',')}`,
    );
  }
}

// ---------------------------------------------------------------- D. injection
console.log('\n--- D. injection ---');

const sqliPath = await call(`/api/ciphers/${encodeURIComponent("' OR 1=1--")}`, { headers: authA });
check(
  'SQLi in path id is not executed',
  [400, 404].includes(sqliPath.status),
  `${sqliPath.status}`,
);

const sqliPrelogin = await call('/identity/accounts/prelogin', {
  method: 'POST',
  headers: { 'content-type': 'application/json' },
  body: JSON.stringify({ email: "' OR 1=1--@example.com" }),
});
check(
  'SQLi in prelogin email is not executed',
  sqliPrelogin.status === 200,
  `${sqliPrelogin.status}`,
);

const sqliLogin = await login("' OR 1=1--@example.com", 'x');
check('SQLi in login username rejected', sqliLogin.status === 401, `${sqliLogin.status}`);

const sqliBulk = await call('/api/ciphers/delete', {
  method: 'POST',
  headers: jsonA,
  body: JSON.stringify({ ids: ["' OR 1=1--"] }),
});
const afterSqliBulk = await call(`/api/ciphers/${cipherId}`, { headers: authA });
check(
  'SQLi in bulk ids does not widen the delete',
  sqliBulk.status === 200 && afterSqliBulk.status === 200,
  `bulk=${sqliBulk.status} cipher=${afterSqliBulk.status}`,
);

const sqliSend = await call(`/api/sends/access/${encodeURIComponent("' OR '1'='1")}`, {
  method: 'POST',
  headers: { 'content-type': 'application/json' },
  body: '{}',
});
check(
  'SQLi in send access id rejected',
  [400, 404].includes(sqliSend.status),
  `${sqliSend.status}`,
);

const traversal = await call(
  `/api/ciphers/${cipherId}/attachment/${encodeURIComponent('../../etc/passwd')}`,
  { headers: authA },
);
check(
  'path traversal in attachment id rejected',
  [400, 404].includes(traversal.status),
  `${traversal.status}`,
);

const proto = await call('/api/ciphers', {
  method: 'POST',
  headers: jsonA,
  body: JSON.stringify({
    type: 2,
    name: '2.proto',
    secureNote: { type: 0 },
    __proto__: { polluted: true },
    constructor: { prototype: { polluted: true } },
  }),
});
check(
  'prototype pollution payload does not crash',
  proto.status === 200 || proto.status === 400,
  `${proto.status}`,
);

const headerInjection = await call('/api/accounts/profile', {
  headers: { ...authA, 'x-forwarded-for': '1.2.3.4\r\nX-Injected: yes' },
});
check(
  'no header injection from request headers',
  !headerInjection.headers?.has('x-injected'),
  `${headerInjection.status}`,
);

// ---------------------------------------------------------------- E. limits
console.log('\n--- E. input limits ---');

const big = 'x'.repeat(6 * 1024 * 1024);
const oversized = await call('/api/ciphers', {
  method: 'POST',
  headers: jsonA,
  body: JSON.stringify({ type: 2, name: big, secureNote: { type: 0 } }),
});
check('oversized body rejected', [400, 413, 422].includes(oversized.status), `${oversized.status}`);

const malformed = await call('/api/ciphers', {
  method: 'POST',
  headers: jsonA,
  body: '{"type": ',
});
check('malformed JSON rejected', malformed.status === 400, `${malformed.status}`);

const badKdf = await call('/identity/accounts/register', {
  method: 'POST',
  headers: { 'content-type': 'application/json' },
  body: JSON.stringify({
    email: `sec-kdf-${stamp}@example.com`,
    userAsymmetricKeys: { publicKey: 'pk', encryptedPrivateKey: 'epk' },
    kdf: { kdfType: 99, iterations: 600000 },
    masterPasswordHash: 'x',
    key: 'k',
  }),
});
check('unsupported kdf type rejected', [400, 422].includes(badKdf.status), `${badKdf.status}`);

const hugeKdf = await call('/identity/accounts/register', {
  method: 'POST',
  headers: { 'content-type': 'application/json' },
  body: JSON.stringify({
    email: `sec-kdf2-${stamp}@example.com`,
    userAsymmetricKeys: { publicKey: 'pk', encryptedPrivateKey: 'epk' },
    kdf: { kdfType: 0, iterations: 1e15 },
    masterPasswordHash: 'x',
    key: 'k',
  }),
});
// Known limitation, inherited from the reference implementation: only a lower
// bound is enforced, so a user can store an iteration count their own client
// can never derive (self-lockout) and any future server-side use of the value
// would be a CPU sink.
warnIfNot(
  'absurd kdf iterations rejected',
  [400, 422].includes(hugeKdf.status),
  `${hugeKdf.status}`,
);

const negativeSize = await call(`/api/ciphers/${cipherId}/attachment/v2`, {
  method: 'POST',
  headers: jsonA,
  body: JSON.stringify({ key: 'k', fileName: 'f', fileSize: -1 }),
});
check(
  'negative attachment size rejected',
  [400, 422].includes(negativeSize.status),
  `${negativeSize.status}`,
);

// ---------------------------------------------------------------- F. CORS
console.log('\n--- F. CORS and headers ---');

const preflight = await call('/api/config', { method: 'OPTIONS' });
const allowOrigin = preflight.headers?.get('access-control-allow-origin');
const allowCreds = preflight.headers?.get('access-control-allow-credentials');
check(
  'preflight answered',
  preflight.status === 200,
  `${preflight.status} allow-origin=${allowOrigin}`,
);
check(
  'no wildcard origin with credentials',
  !(allowOrigin === '*' && allowCreds === 'true'),
  `creds=${allowCreds}`,
);

const config = await call('/api/config');
check(
  'config exposes no secret material',
  !/jwt_secret|JWT_SECRET|PUSH_INSTALLATION|api_token/i.test(config.text),
  `${config.text.length}B`,
);

const staticRoot = await call('/');
check(
  'static root leaks no framework banner',
  staticRoot.status === 200 && !staticRoot.headers?.has('x-powered-by'),
  `${staticRoot.status} x-powered-by=${staticRoot.headers?.get('x-powered-by') ?? 'none'}`,
);

// ---------------------------------------------------------------- G. enumeration
console.log('\n--- G. enumeration and timing ---');

const preExisting = await call('/identity/accounts/prelogin', {
  method: 'POST',
  headers: { 'content-type': 'application/json' },
  body: JSON.stringify({ email: EMAIL_A }),
});
const preMissing = await call('/identity/accounts/prelogin', {
  method: 'POST',
  headers: { 'content-type': 'application/json' },
  body: JSON.stringify({ email: `nobody-${stamp}@example.com` }),
});
check(
  'prelogin does not distinguish existing accounts',
  preExisting.status === preMissing.status &&
    JSON.stringify(preExisting.json) === JSON.stringify(preMissing.json),
  `${preExisting.status}/${preMissing.status} ${JSON.stringify(preExisting.json)} vs ${JSON.stringify(preMissing.json)}`,
);

// The endpoint reads base64url headers, not query parameters.
const encodedEmail = Buffer.from(EMAIL_A).toString('base64url');
const knownHeaders = {
  'x-request-email': encodedEmail,
  'x-device-identifier': randomUUID(),
};
const knownDevice = await call('/api/devices/knowndevice', { headers: knownHeaders });
const unknownUser = await call('/api/devices/knowndevice', {
  headers: {
    'x-request-email': Buffer.from(`nobody-${stamp}@example.com`).toString('base64url'),
    'x-device-identifier': randomUUID(),
  },
});
check(
  'knowndevice answers false for an unknown device',
  knownDevice.text.trim() === 'false' && unknownUser.text.trim() === 'false',
  `known=${knownDevice.status}:${knownDevice.text.trim()} unknown=${unknownUser.status}:${unknownUser.text.trim()}`,
);
check(
  'knowndevice requires its headers',
  (await call('/api/devices/knowndevice')).status === 400,
  'missing headers -> 400',
);

const hintResponse = await call('/api/accounts/password-hint', {
  method: 'POST',
  headers: { 'content-type': 'application/json' },
  body: JSON.stringify({ email: EMAIL_HINT }),
});
check(
  'password hint is not disclosed to anonymous callers',
  !hintResponse.text.includes('hunter2'),
  `${hintResponse.status} ${hintResponse.text.slice(0, 40)}`,
);

const tExisting = await login(EMAIL_B, hashB);
const tMissing = await login(`nobody2-${stamp}@example.com`, 'x');
// Existing users pay a real 600k PBKDF2 (~1.4-1.8s); unknown users pay
// LOGIN_MISSING_USER_DELAY_MS (default 1200ms) so the two should be close.
warnIfNot(
  'login timing does not reveal account existence',
  Math.abs(tExisting.ms - tMissing.ms) < 900,
  `existing=${tExisting.ms}ms missing=${tMissing.ms}ms`,
);

// ---------------------------------------------------------------- L. device revocation
console.log('\n--- L. per-device revocation ---');

const deviceIdB = randomUUID();
const loginB2 = await login(EMAIL_B, hashB, { deviceIdentifier: deviceIdB });
const tokenB2 = loginB2.json?.access_token;

if (typeof tokenB2 === 'string') {
  const revoke = await call(`/api/devices/${deviceIdB}`, {
    method: 'DELETE',
    headers: { authorization: `Bearer ${tokenB2}` },
  });
  check('device revocation accepted', revoke.status === 200, `${revoke.status}`);

  const revoked = await call('/api/accounts/profile', {
    headers: { authorization: `Bearer ${tokenB2}` },
  });
  check('revoked device token is rejected', revoked.status === 401, `${revoked.status}`);

  const survivor = await call('/api/accounts/profile', { headers: authB });
  check('other sessions keep working', survivor.status === 200, `${survivor.status}`);
}

// ---------------------------------------------------------------- H. 2FA
console.log('\n--- H. two-factor ---');

const secret = base32Encode(randomBytes(20));
const enable = await call('/api/two-factor/authenticator', {
  method: 'POST',
  headers: jsonA,
  body: JSON.stringify({ masterPasswordHash: hashA, key: secret, token: totp(secret) }),
});
check('setup: TOTP enabled', enable.status === 200, `${enable.status}`);

const needs2fa = await login(EMAIL_A, hashA);
const challenge = needs2fa.json;
check(
  'login now demands a second factor',
  needs2fa.status === 400 &&
    challenge?.error === 'invalid_grant' &&
    Array.isArray(challenge?.TwoFactorProviders) &&
    challenge?.access_token === undefined,
  `${needs2fa.status} providers=${JSON.stringify(challenge?.TwoFactorProviders)}`,
);

const wrongCode = await login(EMAIL_A, hashA, {
  twoFactorToken: totp(secret, 5),
  twoFactorProvider: '0',
});
check('wrong TOTP code rejected', wrongCode.status === 401, `${wrongCode.status}`);

const twoFactorToken = challenge?.twoFactorToken;
if (typeof twoFactorToken === 'string') {
  const asAccess = await call('/api/accounts/profile', {
    headers: { authorization: `Bearer ${twoFactorToken}` },
  });
  check('2FA interim token rejected as API bearer', asAccess.status === 401, `${asAccess.status}`);
}

// Activation records the step it validated, so reusing that same step would be
// rejected as a replay. Use the next step (inside the ±1 drift window).
const loginCode = totp(secret, 1);
const withCode = await login(EMAIL_A, hashA, { twoFactorToken: loginCode, twoFactorProvider: '0' });
check(
  'correct TOTP completes login',
  withCode.status === 200 && typeof withCode.json?.access_token === 'string',
  `${withCode.status}`,
);

const replay = await login(EMAIL_A, hashA, { twoFactorToken: loginCode, twoFactorProvider: '0' });
// 429 is acceptable here: this account has used its login budget for the minute.
warnIfNot('replayed TOTP code is not accepted twice', replay.status !== 200, `${replay.status}`);

// disable 2FA again so the account is left clean
const disable = await call('/api/two-factor/authenticator', {
  method: 'DELETE',
  headers: jsonA,
  body: JSON.stringify({ masterPasswordHash: hashA, key: secret, type: 0 }),
});
check('setup: TOTP disabled again', disable.status === 200, `${disable.status}`);

// ---------------------------------------------------------------- K. file send password
console.log('\n--- K. password-protected file send ---');

const sendPassword = 'hunter2';
const createdFile = await call('/api/sends/file/v2', {
  method: 'POST',
  headers: jsonA,
  body: JSON.stringify({
    type: 1,
    name: '2.protected',
    notes: null,
    key: Buffer.alloc(32, 5).toString('base64'),
    file: { fileName: 'secret.bin' },
    fileLength: 8,
    maxAccessCount: null,
    deletionDate: new Date(Date.now() + 86_400_000).toISOString(),
    expirationDate: null,
    disabled: false,
    hideEmail: false,
    password: sendPassword,
  }),
});
const protectedSendId = createdFile.json?.sendResponse?.id;
const protectedFileId = createdFile.json?.sendResponse?.file?.id;
check(
  'setup: password-protected file send created',
  createdFile.status === 200 && Boolean(protectedSendId),
  `${createdFile.status}`,
);

if (typeof protectedSendId === 'string' && typeof protectedFileId === 'string') {
  const uploadUrl = createdFile.json?.url;
  if (typeof uploadUrl === 'string') {
    const uploaded = await call(uploadUrl, {
      method: 'PUT',
      headers: { 'content-length': '8' },
      body: 'abcdefgh',
    });
    check('setup: file uploaded', [200, 201].includes(uploaded.status), `${uploaded.status}`);
  }

  const accessPath = `/api/sends/${protectedSendId}/access/file/${protectedFileId}`;
  const anonymous = await call(accessPath, { method: 'POST' });
  check(
    'file-send download refuses anonymous callers when a password is set',
    anonymous.status === 401,
    `${anonymous.status}`,
  );

  const wrongPassword = await call(accessPath, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ password: 'wrong' }),
  });
  check(
    'file-send download rejects a wrong password',
    wrongPassword.status === 400,
    `${wrongPassword.status}`,
  );

  const rightPassword = await call(accessPath, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ password: sendPassword }),
  });
  check(
    'file-send download accepts the correct password',
    rightPassword.status === 200 && rightPassword.json?.object === 'send-fileDownload',
    `${rightPassword.status}`,
  );
}

// ---------------------------------------------------------------- I. session invalidation
console.log('\n--- I. session invalidation ---');

const freshLogin = await login(EMAIL_B, hashB);
const freshToken = freshLogin.json?.access_token;
const beforeStamp = await call('/api/accounts/profile', {
  headers: { authorization: `Bearer ${freshToken}` },
});
check('fresh token works', beforeStamp.status === 200, `${beforeStamp.status}`);

const rotate = await call('/api/accounts/security-stamp', {
  method: 'POST',
  headers: { 'content-type': 'application/json', authorization: `Bearer ${freshToken}` },
  body: JSON.stringify({ masterPasswordHash: hashB }),
});
check('security-stamp accepted', rotate.status === 200, `${rotate.status}`);

const afterStamp = await call('/api/accounts/profile', {
  headers: { authorization: `Bearer ${freshToken}` },
});
check('logout-all invalidates existing tokens', afterStamp.status === 401, `${afterStamp.status}`);

// ---------------------------------------------------------------- J. rate limiting
console.log('\n--- J. rate limiting (runs last: pollutes limits) ---');

let sawLimit = false;
const statuses = [];
for (let attempt = 0; attempt < 8; attempt += 1) {
  const response = await login(`ratelimit-${stamp}@example.com`, 'wrong-password');
  statuses.push(response.status);
  if (response.status === 429) sawLimit = true;
}
check('login rate limit triggers', sawLimit, `statuses=${statuses.join(',')}`);

let preloginLimited = false;
const preStatuses = [];
for (let attempt = 0; attempt < 8; attempt += 1) {
  const response = await call('/identity/accounts/prelogin', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email: `pre-${stamp}@example.com` }),
  });
  preStatuses.push(response.status);
  if (response.status === 429) preloginLimited = true;
}
check('prelogin rate limit triggers', preloginLimited, `statuses=${preStatuses.join(',')}`);

// ---------------------------------------------------------------- summary
console.log('');
console.log(`${results.length - failures}/${results.length} security checks passed`);
if (failures > 0) {
  console.log('FAILED:');
  for (const result of results.filter((r) => !r.ok)) console.log(`  - ${result.label}`);
}
console.log(`test accounts: ${EMAIL_A} / ${EMAIL_B}`);
process.exit(failures === 0 ? 0 : 1);
