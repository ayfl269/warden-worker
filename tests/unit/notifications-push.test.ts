import { describe, expect, it, vi } from 'vitest';

import type { Env } from '../../src/env';
import {
  buildPushEnvelope,
  type FetchLike,
  getRelayToken,
  type PushConfig,
  pushConfig,
  relayTokenCacheUrl,
  sendPush,
  unregisterPushDevice,
  userPushPayload,
} from '../../src/notifications/push';

function envWith(values: Partial<Env>): Env {
  return values as Env;
}

const CONFIG: PushConfig = {
  relayUri: 'https://push.example.com',
  identityUri: 'https://identity.example.com',
  installationId: 'install-1',
  key: 'secret-key',
};

interface CacheRecord {
  puts: Array<{ url: string; body: string; maxAge: string | null }>;
}

function fakeCache(hit?: string): CacheRecord & {
  match(request: string): Promise<Response | undefined>;
  put(request: string, response: Response): Promise<void>;
} {
  const record = {
    puts: [] as CacheRecord['puts'],
    async match(_request: string) {
      return hit === undefined ? undefined : new Response(hit);
    },
    async put(request: string, response: Response) {
      record.puts.push({
        url: request,
        body: await response.text(),
        maxAge: response.headers.get('cache-control'),
      });
    },
  };
  return record;
}

describe('pushConfig', () => {
  it('is disabled unless PUSH_ENABLED is exactly "true"', () => {
    expect(pushConfig(envWith({}))).toBeNull();
    expect(pushConfig(envWith({ PUSH_ENABLED: 'false' }))).toBeNull();
    expect(pushConfig(envWith({ PUSH_ENABLED: 'TRUE' }))).toBeNull();
  });

  it('requires both installation secrets', () => {
    expect(pushConfig(envWith({ PUSH_ENABLED: 'true' }))).toBeNull();
    expect(pushConfig(envWith({ PUSH_ENABLED: 'true', PUSH_INSTALLATION_ID: 'id' }))).toBeNull();
  });

  it('uses the documented defaults and trims custom URIs', () => {
    expect(
      pushConfig(
        envWith({
          PUSH_ENABLED: 'true',
          PUSH_INSTALLATION_ID: 'id',
          PUSH_INSTALLATION_KEY: 'key',
        }),
      ),
    ).toEqual({
      relayUri: 'https://push.bitwarden.com',
      identityUri: 'https://identity.bitwarden.com',
      installationId: 'id',
      key: 'key',
    });

    expect(
      pushConfig(
        envWith({
          PUSH_ENABLED: 'true',
          PUSH_INSTALLATION_ID: 'id',
          PUSH_INSTALLATION_KEY: 'key',
          PUSH_RELAY_URI: 'https://relay.example.com/',
          PUSH_IDENTITY_URI: 'https://id.example.com/',
        }),
      ),
    ).toMatchObject({
      relayUri: 'https://relay.example.com',
      identityUri: 'https://id.example.com',
    });
  });
});

describe('relay token cache key', () => {
  it('is stable, changes with credentials and never leaks the secret', () => {
    const first = relayTokenCacheUrl(CONFIG);
    expect(first).toBe(relayTokenCacheUrl(CONFIG));
    expect(first).not.toContain('secret-key');
    expect(relayTokenCacheUrl({ ...CONFIG, key: 'other' })).not.toBe(first);
  });
});

describe('getRelayToken', () => {
  it('requests a client_credentials token and caches it', async () => {
    const cache = fakeCache();
    const calls: Array<{ url: string; body: string }> = [];

    const fetchImpl: FetchLike = (async (input: RequestInfo | URL, init?: RequestInit) => {
      calls.push({
        url: String(input),
        body: typeof init?.body === 'string' ? init.body : '',
      });
      return new Response(JSON.stringify({ access_token: 'relay-token', expires_in: 100 }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    }) as FetchLike;

    const token = await getRelayToken(CONFIG, fetchImpl, cache);
    expect(token).toBe('relay-token');
    expect(calls).toHaveLength(1);
    expect(calls[0]?.url).toBe('https://identity.example.com/connect/token');

    const params = new URLSearchParams(calls[0]?.body ?? '');
    expect(params.get('grant_type')).toBe('client_credentials');
    expect(params.get('scope')).toBe('api.push');
    expect(params.get('client_id')).toBe('installation.install-1');
    expect(params.get('client_secret')).toBe('secret-key');

    expect(cache.puts).toHaveLength(1);
    expect(cache.puts[0]?.body).toBe('relay-token');
    // max(expires_in / 2, 60)
    expect(cache.puts[0]?.maxAge).toBe('max-age=60');
  });

  it('uses the cached token when present', async () => {
    const cache = fakeCache('cached-token');
    const fetchImpl = vi.fn() as unknown as FetchLike;

    expect(await getRelayToken(CONFIG, fetchImpl, cache)).toBe('cached-token');
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it('throws when the identity endpoint fails', async () => {
    const fetchImpl = (async () => new Response('nope', { status: 500 })) as FetchLike;
    await expect(getRelayToken(CONFIG, fetchImpl, fakeCache())).rejects.toThrow('push identity');
  });
});

describe('buildPushEnvelope', () => {
  it('uses the exact envelope keys', () => {
    const envelope = buildPushEnvelope({
      userId: 'u1',
      type: 1,
      payload: { id: 'c1' },
      deviceId: 'd1',
      identifier: 'd1',
    });
    expect(Object.keys(envelope)).toEqual([
      'userId',
      'organizationId',
      'deviceId',
      'identifier',
      'type',
      'payload',
      'clientType',
      'installationId',
    ]);
    expect(envelope).toMatchObject({
      userId: 'u1',
      organizationId: null,
      deviceId: 'd1',
      identifier: 'd1',
      type: 1,
      payload: { id: 'c1' },
      clientType: null,
      installationId: null,
    });
  });

  it('builds the user payload', () => {
    expect(userPushPayload('u1', '2026-01-01T00:00:00.000Z')).toEqual({
      userId: 'u1',
      date: '2026-01-01T00:00:00.000Z',
    });
  });
});

describe('sendPush gating', () => {
  it('does nothing when push is disabled', async () => {
    const fetchImpl = vi.fn() as unknown as FetchLike;
    await sendPush(envWith({}), 'u1', 0, {}, undefined, fetchImpl);
    expect(fetchImpl).not.toHaveBeenCalled();
  });
});

describe('unregisterPushDevice', () => {
  it('posts to /push/delete/{uuid} and swallows failures', async () => {
    const urls: string[] = [];
    const fetchImpl: FetchLike = (async (input: RequestInfo | URL) => {
      urls.push(String(input));
      return new Response(JSON.stringify({ access_token: 't', expires_in: 3600 }), { status: 200 });
    }) as FetchLike;

    await unregisterPushDevice(CONFIG, 'push-uuid', fetchImpl);
    expect(urls.some((url) => url.endsWith('/push/delete/push-uuid'))).toBe(true);
  });
});
