import { getDb } from '../db/client';
import type { Env } from '../env';

/**
 * Mobile push relay, mirroring `src/push.rs`.
 *
 * Warden does not sign a JWT itself: it obtains a relay token via OAuth2
 * `client_credentials` and forwards notifications to Bitwarden's push service.
 */

export interface PushConfig {
  relayUri: string;
  identityUri: string;
  installationId: string;
  key: string;
}

const DEFAULT_RELAY_URI = 'https://push.bitwarden.com';
const DEFAULT_IDENTITY_URI = 'https://identity.bitwarden.com';
const TOKEN_CACHE_URL = 'https://push-token.internal/relay-token';

export type FetchLike = typeof fetch;

/** Push is only enabled by the exact literal `true`. */
export function pushConfig(env: Env): PushConfig | null {
  if (env.PUSH_ENABLED !== 'true') return null;

  const installationId = env.PUSH_INSTALLATION_ID;
  const key = env.PUSH_INSTALLATION_KEY;
  if (installationId === undefined || key === undefined) return null;

  return {
    relayUri: (env.PUSH_RELAY_URI ?? DEFAULT_RELAY_URI).replace(/\/+$/, ''),
    identityUri: (env.PUSH_IDENTITY_URI ?? DEFAULT_IDENTITY_URI).replace(/\/+$/, ''),
    installationId,
    key,
  };
}

/** Stable cache key derived from the identity URI + installation credentials. */
export function relayTokenCacheUrl(cfg: PushConfig): string {
  const raw = `${cfg.identityUri}|${cfg.installationId}|${cfg.key}`;
  // djb2 hash is enough: the cache key must not leak the credentials.
  let hash = 5381;
  for (let index = 0; index < raw.length; index += 1) {
    hash = ((hash << 5) + hash + raw.charCodeAt(index)) | 0;
  }
  return `${TOKEN_CACHE_URL}?h=${(hash >>> 0).toString(16)}`;
}

interface TokenCache {
  match(request: string): Promise<Response | undefined>;
  put(request: string, response: Response): Promise<void>;
}

function defaultCache(): TokenCache | null {
  const store = (globalThis as { caches?: { default?: TokenCache } }).caches;
  return store?.default ?? null;
}

/** Obtain (and cache) the relay access token. */
export async function getRelayToken(
  cfg: PushConfig,
  fetchImpl: FetchLike = fetch,
  cache: TokenCache | null = defaultCache(),
): Promise<string> {
  const cacheUrl = relayTokenCacheUrl(cfg);

  if (cache !== null) {
    try {
      const hit = await cache.match(cacheUrl);
      if (hit !== undefined) {
        const text = await hit.text();
        if (text.length > 0) return text;
      }
    } catch {
      // Cache failures are non-fatal.
    }
  }

  const response = await fetchImpl(`${cfg.identityUri}/connect/token`, {
    method: 'POST',
    headers: {
      'content-type': 'application/x-www-form-urlencoded',
      accept: 'application/json',
    },
    body: new URLSearchParams({
      grant_type: 'client_credentials',
      scope: 'api.push',
      client_id: `installation.${cfg.installationId}`,
      client_secret: cfg.key,
    }).toString(),
  });

  if (!response.ok) {
    throw new Error(`push identity responded ${response.status}`);
  }

  const body = (await response.json()) as { access_token?: unknown; expires_in?: unknown };
  if (typeof body.access_token !== 'string' || body.access_token.length === 0) {
    throw new Error('push identity response missing access_token');
  }

  const expiresIn = typeof body.expires_in === 'number' ? body.expires_in : 3600;
  if (cache !== null) {
    try {
      await cache.put(
        cacheUrl,
        new Response(body.access_token, {
          headers: {
            'content-type': 'text/plain',
            'cache-control': `max-age=${Math.max(Math.floor(expiresIn / 2), 60)}`,
          },
        }),
      );
    } catch {
      // Cache failures are non-fatal.
    }
  }

  return body.access_token;
}

/** Push envelope shared by every notification type. */
export function buildPushEnvelope(options: {
  userId: string;
  type: number;
  payload: Record<string, unknown>;
  deviceId?: string | null;
  identifier?: string | null;
}): Record<string, unknown> {
  return {
    userId: options.userId,
    organizationId: null,
    deviceId: options.deviceId ?? null,
    identifier: options.identifier ?? null,
    type: options.type,
    payload: options.payload,
    clientType: null,
    installationId: null,
  };
}

async function authorizedFetch(
  cfg: PushConfig,
  path: string,
  init: RequestInit,
  fetchImpl: FetchLike,
): Promise<Response> {
  const token = await getRelayToken(cfg, fetchImpl);
  const headers = new Headers(init.headers);
  headers.set('authorization', `Bearer ${token}`);
  headers.set('content-type', 'application/json');
  return fetchImpl(`${cfg.relayUri}${path}`, { ...init, headers });
}

/** Register a device with the relay; returns the push uuid to persist. */
export async function registerPushDevice(
  env: Env,
  cfg: PushConfig,
  device: {
    identifier: string;
    userId: string;
    type: number;
    pushUuid: string | null;
    pushToken: string;
  },
  fetchImpl: FetchLike = fetch,
): Promise<string> {
  const pushUuid = device.pushUuid ?? crypto.randomUUID();

  const response = await authorizedFetch(
    cfg,
    '/push/register',
    {
      method: 'POST',
      body: JSON.stringify({
        deviceId: pushUuid,
        pushToken: device.pushToken,
        userId: device.userId,
        type: device.type,
        identifier: device.identifier,
        installationId: cfg.installationId,
      }),
    },
    fetchImpl,
  );

  if (!response.ok) {
    throw new Error(`push register responded ${response.status}`);
  }

  void env;
  return pushUuid;
}

export async function unregisterPushDevice(
  cfg: PushConfig,
  pushUuid: string,
  fetchImpl: FetchLike = fetch,
): Promise<void> {
  try {
    const response = await authorizedFetch(
      cfg,
      `/push/delete/${pushUuid}`,
      { method: 'POST', body: '{}' },
      fetchImpl,
    );
    if (!response.ok) {
      console.warn(`[push] unregister responded ${response.status}`);
    }
  } catch (error) {
    console.warn('[push] unregister failed', error);
  }
}

/** Whether the user has at least one push-capable device. */
async function userHasPushDevice(env: Env, userId: string): Promise<boolean> {
  try {
    const row = await getDb(env)
      .prepare(
        'SELECT COUNT(*) AS c FROM devices WHERE user_id = ?1 AND push_token IS NOT NULL AND push_uuid IS NOT NULL',
      )
      .bind(userId)
      .first<{ c: number }>();
    return (row?.c ?? 0) > 0;
  } catch {
    return false;
  }
}

async function resolveDevice(
  env: Env,
  userId: string,
  contextId: string | undefined,
): Promise<{ identifier: string } | null> {
  if (contextId === undefined) return null;
  try {
    const row = await getDb(env)
      .prepare('SELECT identifier FROM devices WHERE identifier = ?1 AND user_id = ?2')
      .bind(contextId, userId)
      .first<{ identifier: string }>();
    return row;
  } catch {
    return null;
  }
}

/** Fire a push notification; never throws. */
export async function sendPush(
  env: Env,
  userId: string,
  type: number,
  payload: Record<string, unknown>,
  contextId?: string,
  fetchImpl: FetchLike = fetch,
): Promise<void> {
  const cfg = pushConfig(env);
  if (cfg === null) return;
  if (!(await userHasPushDevice(env, userId))) return;

  const device = await resolveDevice(env, userId, contextId);
  const envelope = buildPushEnvelope({
    userId,
    type,
    payload,
    deviceId: device?.identifier ?? null,
    identifier: device?.identifier ?? null,
  });

  try {
    const response = await authorizedFetch(
      cfg,
      '/push/send',
      { method: 'POST', body: JSON.stringify(envelope) },
      fetchImpl,
    );
    if (!response.ok) {
      console.warn(`[push] send responded ${response.status}`);
    }
  } catch (error) {
    console.warn('[push] send failed', error);
  }
}

/** User-level push payload (`{userId, date}`). */
export function userPushPayload(userId: string, date: string): Record<string, unknown> {
  return { userId, date };
}
