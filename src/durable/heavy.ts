import { DurableObject } from 'cloudflare:workers';

import { makeApp } from '../app';
import type { Env } from '../env';

/**
 * CPU-heavy endpoints run here, with a 30s CPU budget instead of the free
 * plan's per-request limit on the main worker.
 *
 * The DO deliberately reuses the exact same Hono app (single source of truth
 * for business logic), mirroring `src/durable/heavy_do.rs`.
 */
export class HeavyDo extends DurableObject<Env> {
  override async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    // Intentionally ignores BASE_URL: the Rust implementation derives the base
    // URL from the forwarded request only.
    const baseUrl = `${url.protocol}//${url.host}`;
    const app = makeApp({ baseUrlOverride: baseUrl });
    return app.fetch(request, this.env, this.ctx as unknown as ExecutionContext);
  }
}
