import pbkdf2Module from '../wasm/pbkdf2.wasm';
import { makeApp } from './app';
import { initPbkdf2Wasm } from './auth/pbkdf2Wasm';
import { base64UrlNoPadToBytes } from './auth/base64';
import { HeavyDo } from './durable/heavy';
import { NotifyDo } from './durable/notify';
import type { Env } from './env';
import { handleStreaming, isStreamingRoute } from './handlers/streaming';
import { shouldOffloadHeavy, shouldOffloadToken } from './routing/heavyRoutes';

export { HeavyDo, NotifyDo };

// Preferred PBKDF2 backend: hand-written AssemblyScript module (2 compressions
// per HMAC iteration instead of 4). Falls back to node:crypto then noble.
initPbkdf2Wasm(pbkdf2Module);

/** Single app instance for the main worker; HeavyDo builds its own per request. */
const app = makeApp();

/** Strip all trailing slashes, leaving `/` untouched (matches `entry.js`). */
function normalizePathname(pathname: string): string {
  if (pathname === '/') return '/';
  return pathname.replace(/\/+$/, '');
}

function normalizeUsername(value: unknown): string | null {
  if (typeof value !== 'string') return null;
  const trimmed = value.trim().toLowerCase();
  return trimmed.length > 0 ? trimmed : null;
}

const BEARER_PATTERN = /^\s*Bearer\s+(.+?)\s*$/i;

function bearerToken(headers: Headers): string | null {
  const value = headers.get('authorization');
  if (value === null) return null;
  return BEARER_PATTERN.exec(value)?.[1] ?? null;
}

/** Unverified JWT payload read, used only to pick a HeavyDo shard. */
function decodeJwtSubject(token: string): string | null {
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  const payload = parts[1];
  if (payload === undefined) return null;

  try {
    const json = new TextDecoder().decode(base64UrlNoPadToBytes(payload));
    const parsed = JSON.parse(json) as { sub?: unknown };
    return typeof parsed.sub === 'string' && parsed.sub.length > 0 ? parsed.sub : null;
  } catch {
    return null;
  }
}

async function heavyDoShardKey(request: Request, pathname: string): Promise<string | null> {
  // Registration is unauthenticated; the body carries `email` as username.
  if (
    pathname === '/identity/accounts/register' ||
    pathname === '/identity/accounts/register/finish'
  ) {
    try {
      const body = (await request.clone().json()) as { email?: unknown };
      return normalizeUsername(body?.email);
    } catch {
      return null;
    }
  }

  const token = bearerToken(request.headers);
  return token === null ? null : decodeJwtSubject(token);
}

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);
    url.pathname = normalizePathname(url.pathname);
    // Rebuild the request so every downstream layer sees the normalized path
    // (same trick as `entry.js`).
    request = new Request(url, request as unknown as RequestInit);

    const method = request.method.toUpperCase();

    // WebSocket notification hubs
    if (
      env.NOTIFY_DO !== undefined &&
      method === 'GET' &&
      (url.pathname === '/notifications/hub' || url.pathname === '/notifications/anonymous-hub')
    ) {
      const id = env.NOTIFY_DO.idFromName('global');
      return env.NOTIFY_DO.get(id).fetch(request);
    }

    // CPU-heavy offload
    if (env.HEAVY_DO !== undefined) {
      if (url.pathname === '/identity/connect/token' && method === 'POST') {
        // Only the plain password grant is expensive. `authrequest` logins skip
        // master-password verification, and refresh_token is a cheap HS256
        // verify, so both stay on the main worker.
        const body = await request.clone().text();
        const params = new URLSearchParams(body);
        const grantType = params.get('grant_type');
        const authRequest = params.get('authrequest') ?? params.get('authRequest');

        if (shouldOffloadToken(grantType, authRequest)) {
          const shard = normalizeUsername(params.get('username')) ?? 'default';
          const id = env.HEAVY_DO.idFromName(`user:${shard}`);
          return env.HEAVY_DO.get(id).fetch(request, { body });
        }
      } else {
        if (shouldOffloadHeavy(url.pathname, method)) {
          const shard = (await heavyDoShardKey(request, url.pathname)) ?? 'default';
          const id = env.HEAVY_DO.idFromName(`user:${shard}`);
          return env.HEAVY_DO.get(id).fetch(request);
        }
      }
    }

    // Zero-copy attachment / Send file transfers bypass the JSON app entirely.
    if (isStreamingRoute(method, url.pathname)) {
      return handleStreaming(request, env, url);
    }

    return app.fetch(request, env, ctx);
  },

  async scheduled(
    _controller: ScheduledController,
    _env: Env,
    _ctx: ExecutionContext,
  ): Promise<void> {
    // P3 wires the five purge tasks (stale attachments, soft-deleted ciphers,
    // stale pending sends, expired sends, expired auth requests) in order.
    console.error('[cron] scheduled handler is not implemented yet (P3)');
  },
};
