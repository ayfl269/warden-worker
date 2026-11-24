import { Hono } from 'hono';

import type { Env } from './env';
import { isAppError } from './errors';
import { apiRouter } from './router';
import type { AppEnv } from './types';

export interface AppOptions {
  /**
   * Base URL override.
   *
   * HeavyDo computes it from the request URI and ignores `BASE_URL`, matching
   * `src/durable/heavy_do.rs`. The main worker passes nothing so that
   * `BASE_URL` (when configured) wins, matching `src/lib.rs`.
   */
  baseUrlOverride?: string;
}

const CORS_PREFLIGHT_HEADERS: Record<string, string> = {
  'access-control-allow-origin': '*',
  'access-control-allow-methods': '*',
  'access-control-allow-headers': '*',
};

function resolveBaseUrl(env: Env, requestUrl: string): string {
  if (env.BASE_URL !== undefined) {
    return env.BASE_URL.replace(/\/+$/, '');
  }
  const url = new URL(requestUrl);
  return `${url.protocol}//${url.host}`;
}

/** Match a Hono route pattern (`/a/:id/*`) against a pathname. */
function matchRoutePath(pattern: string, pathname: string): boolean {
  if (pattern === '*' || pattern === '/*') return true;

  const patternSegments = pattern.split('/').filter((segment) => segment.length > 0);
  const pathSegments = pathname.split('/').filter((segment) => segment.length > 0);

  for (let index = 0; index < patternSegments.length; index += 1) {
    const expected = patternSegments[index] as string;
    if (expected === '*') return true;

    const actual = pathSegments[index];
    if (actual === undefined) return false;
    if (expected.startsWith(':')) continue;
    if (expected !== actual) return false;
  }

  return patternSegments.length === pathSegments.length;
}

/** Methods registered for a path, used to answer 405 like axum does. */
function allowedMethodsFor(app: Hono<AppEnv>, pathname: string): string[] {
  const allowed = new Set<string>();
  for (const route of app.routes) {
    if (route.method === 'ALL') continue;
    if (matchRoutePath(route.path, pathname)) {
      allowed.add(route.method);
    }
  }
  return [...allowed].sort();
}

export function makeApp(options: AppOptions = {}): Hono<AppEnv> {
  const app = new Hono<AppEnv>();

  // Base URL resolution must run before any handler reads `baseUrl`.
  app.use('*', async (c, next) => {
    c.set('baseUrl', options.baseUrlOverride ?? resolveBaseUrl(c.env, c.req.url));
    await next();
  });

  // CORS: equivalent to tower-http's `CorsLayer::new().allow_*(Any)`.
  app.use('*', async (c, next) => {
    if (c.req.method === 'OPTIONS') {
      return new Response(null, { status: 200, headers: CORS_PREFLIGHT_HEADERS });
    }
    await next();
    c.res.headers.set('access-control-allow-origin', '*');
  });

  app.route('/', apiRouter());

  // axum returns an empty 404 body, and 405 + `Allow` when the path exists
  // with a different method. Hono's defaults differ, so both are restored here.
  app.notFound((c) => {
    const pathname = new URL(c.req.url).pathname;
    const allowed = allowedMethodsFor(app, pathname);
    if (allowed.length > 0) {
      return new Response(null, { status: 405, headers: { allow: allowed.join(', ') } });
    }
    return new Response(null, { status: 404 });
  });

  app.onError((error) => {
    if (isAppError(error)) {
      return error.toResponse();
    }
    console.error('[worker] unhandled error', error);
    return new Response(JSON.stringify({ error: 'Internal server error' }), {
      status: 500,
      headers: { 'content-type': 'application/json' },
    });
  });

  return app;
}
