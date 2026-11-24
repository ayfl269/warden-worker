import type { Context } from 'hono';

import { deviceTypeDisplayName } from '../auth/device';
import {
  ACCESS_TOKEN_TTL_SECONDS,
  jwtSecret,
  REFRESH_TOKEN_TTL_SECONDS,
  REMEMBER_TOKEN_ISSUER,
  REMEMBER_TOKEN_TTL_SECONDS,
  type RefreshClaims,
  SEND_ACCESS_ISSUER,
  SEND_ACCESS_TOKEN_TTL_SECONDS,
  signToken,
  verifyToken,
} from '../auth/jwt';
import { missingUserDelayMs, sleep } from '../auth/loginDelay';
import {
  constantTimeEqual,
  generateSalt,
  hashPasswordForStorage,
  verifyPassword,
} from '../auth/password';
import { parsePasswordGrant } from '../auth/tokenRequest';
import { validateTotp } from '../auth/totp';
import { type Db, getDb, nowString, touchUserUpdatedAt } from '../db/client';
import { getOrCreateDevice, setTwoFactorRemember, touchDevice } from '../db/devices';
import { allowTotpDrift, serverPasswordIterations } from '../env';
import { AppError } from '../errors';
import { readForm } from '../http/body';
import { enforceIpRateLimit, enforceRateLimit } from '../http/limits';
import { jsonResponse } from '../http/rawJson';
import { SEND_COLUMNS, type SendRow, uuidFromAccessId, validateSendAccess } from '../models/send';
import { buildSendAccessTokenResponse, buildTokenResponse } from '../models/tokenResponse';
import type { UserRow } from '../models/user';
import type { AppEnv } from '../types';

const INVALID_CREDENTIALS = 'Invalid credentials';
const LOGIN_RATE_MESSAGE = 'Too many login attempts. Please try again later.';

interface TwoFactorRow {
  uuid: string;
  atype: number;
  enabled: number;
  data: string;
  last_used: number;
}

/** The 2FA-required body is served with HTTP 400 and a verbatim payload. */
function twoFactorRequiredBody(): string {
  return JSON.stringify({
    error: 'invalid_grant',
    error_description: 'Two factor required.',
    TwoFactorProviders: ['0'],
    TwoFactorProviders2: { 0: null },
    MasterPasswordPolicy: { Object: 'masterPasswordPolicy' },
  });
}

async function findUserByEmail(db: Db, email: string): Promise<UserRow | null> {
  return db
    .prepare('SELECT * FROM users WHERE email = ?1')
    .bind(email.toLowerCase())
    .first<UserRow>();
}

async function listTwoFactors(db: Db, userId: string): Promise<TwoFactorRow[]> {
  const result = await db
    .prepare('SELECT uuid, atype, enabled, data, last_used FROM twofactor WHERE user_uuid = ?1')
    .bind(userId)
    .all<TwoFactorRow>();
  return result.results ?? [];
}

/** Verify the client hash against the stored server-side PBKDF2 hash. */
function verifyMasterPassword(user: UserRow, clientHash: string): boolean {
  if (user.password_salt === null) {
    // Fresh deployments never hit this; kept for behavioural parity.
    return constantTimeEqual(user.master_password_hash, clientHash);
  }
  return verifyPassword(
    clientHash,
    user.master_password_hash,
    user.password_salt,
    user.password_iterations,
  );
}

/** Upgrade the server-side hash when the global iteration count increases. */
async function migratePasswordHashIfNeeded(
  db: Db,
  user: UserRow,
  clientHash: string,
  targetIterations: number,
): Promise<void> {
  if (user.password_salt !== null && user.password_iterations >= targetIterations) return;

  const salt = generateSalt();
  const hash = hashPasswordForStorage(clientHash, salt, targetIterations);
  await db
    .prepare(
      'UPDATE users SET master_password_hash = ?1, password_salt = ?2, password_iterations = ?3, updated_at = ?4 WHERE id = ?5',
    )
    .bind(hash, salt, targetIterations, nowString(), user.id)
    .run();
}

async function issueTokens(
  env: AppEnv['Bindings'],
  user: UserRow,
  deviceIdentifier: string,
  deviceType: number,
  clientId: string,
  refreshTokenValue: string,
  twoFactorToken?: string,
): Promise<Response> {
  const accessToken = await signToken(
    {
      sub: user.id,
      sstamp: user.security_stamp ?? '',
      premium: true,
      name: user.name ?? 'User',
      email: user.email,
      email_verified: user.email_verified === 1,
      device: deviceIdentifier,
      devicetype: deviceTypeDisplayName(deviceType),
      client_id: clientId,
      scope: ['api', 'offline_access'],
      amr: ['Application'],
    },
    jwtSecret(env, 'JWT_SECRET'),
    ACCESS_TOKEN_TTL_SECONDS,
  );

  const refreshToken = await signToken(
    {
      sub: 'password',
      device_token: refreshTokenValue,
      sstamp: user.security_stamp ?? '',
    },
    jwtSecret(env, 'JWT_REFRESH_SECRET'),
    REFRESH_TOKEN_TTL_SECONDS,
  );

  return jsonResponse(
    buildTokenResponse({
      accessToken,
      refreshToken,
      userKey: user.key,
      privateKey: user.private_key,
      publicKey: user.public_key,
      kdfType: user.kdf_type,
      kdfIterations: user.kdf_iterations,
      kdfMemory: user.kdf_memory,
      kdfParallelism: user.kdf_parallelism,
      email: user.email,
      hasMasterPassword: user.master_password_hash.length > 0,
      ...(twoFactorToken !== undefined ? { twoFactorToken } : {}),
    }),
  );
}

async function passwordGrant(c: Context<AppEnv>, params: URLSearchParams): Promise<Response> {
  const request = parsePasswordGrant(params);

  await enforceRateLimit(
    c.env,
    'LOGIN_RATE_LIMITER',
    `login:${request.username.toLowerCase()}`,
    LOGIN_RATE_MESSAGE,
  );
  await enforceIpRateLimit(
    c.env,
    c.req.raw.headers,
    'LOGIN_RATE_LIMITER',
    'login-ip',
    LOGIN_RATE_MESSAGE,
  );

  const db = getDb(c.env);
  const user = await findUserByEmail(db, request.username);

  if (user === null) {
    await sleep(missingUserDelayMs(c.env));
    throw AppError.unauthorized(INVALID_CREDENTIALS);
  }

  if (!verifyMasterPassword(user, request.password)) {
    throw AppError.unauthorized(INVALID_CREDENTIALS);
  }

  // The device row (and its refresh token) is created before 2FA is checked.
  const device = await getOrCreateDevice(
    db,
    request.device.identifier,
    user.id,
    request.device.name,
    request.device.type,
  );

  const twoFactors = await listTwoFactors(db, user.id);
  const totp = twoFactors.find((row) => row.enabled === 1 && row.atype === 0);
  let twoFactorToken: string | undefined;

  if (totp !== undefined) {
    const provider = request.twoFactorProvider ?? 0;
    if (request.twoFactorToken === undefined) {
      throw AppError.twoFactorRequired(twoFactorRequiredBody());
    }
    if (provider !== 0) {
      throw AppError.badRequest('Invalid two factor provider');
    }

    const step = validateTotp(
      request.twoFactorToken,
      totp.data,
      totp.last_used,
      allowTotpDrift(c.env),
    );
    await db
      .prepare('UPDATE twofactor SET last_used = ?1 WHERE uuid = ?2')
      .bind(step, totp.uuid)
      .run();

    if (request.twoFactorRemember === 1) {
      // The remember token is a JWT bound to this device and stored verbatim so
      // it can be invalidated (logout-all clears the column).
      twoFactorToken = await signToken(
        { sub: device.identifier, user_uuid: user.id, iss: REMEMBER_TOKEN_ISSUER },
        jwtSecret(c.env, 'JWT_REFRESH_SECRET'),
        REMEMBER_TOKEN_TTL_SECONDS,
      );
      await setTwoFactorRemember(db, device.identifier, user.id, twoFactorToken, nowString());
    }
  }

  await migratePasswordHashIfNeeded(db, user, request.password, serverPasswordIterations(c.env));

  await touchDevice(db, device.identifier, user.id, nowString());

  return issueTokens(
    c.env,
    user,
    device.identifier,
    device.type,
    request.clientId,
    device.refresh_token,
    twoFactorToken,
  );
}

async function refreshGrant(c: Context<AppEnv>, params: URLSearchParams): Promise<Response> {
  const raw = params.get('refresh_token');
  if (raw === null || raw.length === 0) {
    throw AppError.apiJson(400, { error: 'invalid_grant' });
  }

  const claims = await verifyToken<RefreshClaims>(raw, jwtSecret(c.env, 'JWT_REFRESH_SECRET'));
  if (claims === null || claims.sub !== 'password') {
    throw AppError.apiJson(400, { error: 'invalid_grant' });
  }

  const db = getDb(c.env);
  const device = await db
    .prepare('SELECT * FROM devices WHERE refresh_token = ?1')
    .bind(claims.device_token)
    .first<{ identifier: string; user_id: string; type: number; refresh_token: string }>();

  if (device === null) {
    throw AppError.apiJson(400, { error: 'invalid_grant' });
  }

  const user = await db
    .prepare('SELECT * FROM users WHERE id = ?1')
    .bind(device.user_id)
    .first<UserRow>();

  if (user === null || !constantTimeEqual(claims.sstamp, user.security_stamp ?? '')) {
    throw AppError.apiJson(400, { error: 'invalid_grant' });
  }

  const now = nowString();
  await touchUserUpdatedAt(db, user.id, now);
  await touchDevice(db, device.identifier, user.id, now);

  return issueTokens(
    c.env,
    user,
    device.identifier,
    device.type,
    params.get('client_id') ?? 'undefined',
    device.refresh_token,
  );
}

async function sendAccessGrant(c: Context<AppEnv>, params: URLSearchParams): Promise<Response> {
  const accessId = params.get('send_id');
  if (accessId === null || accessId.length === 0) {
    throw AppError.apiJson(400, { error: 'invalid_request' });
  }

  let sendId: string;
  try {
    sendId = uuidFromAccessId(accessId);
  } catch {
    throw AppError.apiJson(400, { error: 'invalid_grant' });
  }

  const db = getDb(c.env);
  const send = await db
    .prepare(`SELECT ${SEND_COLUMNS} FROM sends WHERE id = ?1`)
    .bind(sendId)
    .first<SendRow>();
  if (send === null) {
    throw AppError.notFound('Send does not exist or is no longer available');
  }

  validateSendAccess(send, nowString());

  if (send.password_hash !== null) {
    await enforceIpRateLimit(
      c.env,
      c.req.raw.headers,
      'SEND_ACCESS_RATE_LIMITER',
      'send-access',
      'Too many send password attempts. Please try again later.',
    );

    const provided = params.get('password_hash_b64');
    if (provided === null || provided.length === 0) {
      throw AppError.apiJson(400, {
        kind: 'expected_server',
        error: 'invalid_request',
        send_access_error_type: 'password_hash_b64_required',
      });
    }

    // The client sends the base64url-encoded derived hash.
    if (!constantTimeEqual(provided.replace(/=+$/, ''), send.password_hash)) {
      throw AppError.apiJson(400, {
        kind: 'expected_server',
        error: 'invalid_grant',
        send_access_error_type: 'password_hash_b64_invalid',
      });
    }
  }

  await db
    .prepare('UPDATE sends SET access_count = access_count + 1, updated_at = ?1 WHERE id = ?2')
    .bind(nowString(), send.id)
    .run();

  const token = await signToken(
    { sub: send.id, iss: SEND_ACCESS_ISSUER },
    jwtSecret(c.env, 'JWT_SECRET'),
    SEND_ACCESS_TOKEN_TTL_SECONDS,
  );

  return jsonResponse(buildSendAccessTokenResponse(token));
}

/** `POST /identity/connect/token` */
export async function tokenHandler(c: Context<AppEnv>): Promise<Response> {
  const params = await readForm(c.req.raw);
  const grantType = params.get('grant_type');

  if (grantType === 'password') {
    return passwordGrant(c, params);
  }
  if (grantType === 'refresh_token') {
    return refreshGrant(c, params);
  }
  if (grantType === 'send_access') {
    return sendAccessGrant(c, params);
  }

  throw AppError.apiJson(400, { error: 'invalid_grant' });
}
