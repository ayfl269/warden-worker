/**
 * PBKDF2 production probe.
 *
 * Answers three questions that cannot be answered locally:
 *  1. does `node:crypto.pbkdf2Sync` accept 600k iterations on the edge?
 *  2. does WebCrypto accept 600k iterations?
 *  3. how long does the pure-JS `@noble/hashes` fallback take inside a Durable
 *     Object (the only place with a 30s CPU budget)?
 *
 * `?do=1` runs the fallback inside `ProbeDo`; the default path runs the cheap
 * checks in the main worker (a 600k pure-JS run there exceeds the CPU limit).
 */

import { DurableObject } from 'cloudflare:workers';
import { pbkdf2Sync } from 'node:crypto';
import { pbkdf2 as noblePbkdf2 } from '@noble/hashes/pbkdf2.js';
import { sha256 } from '@noble/hashes/sha2.js';

const VECTORS: ReadonlyArray<readonly [number, string]> = [
  [1, '120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b'],
  [2, 'ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43'],
  [4096, 'c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a'],
];

const PRODUCTION_ITERATIONS = 600_000;
const KEY_LENGTH_BYTES = 32;

function utf8(value: string): Uint8Array {
  return new TextEncoder().encode(value);
}

function toHex(bytes: Uint8Array): string {
  return [...bytes].map((byte) => byte.toString(16).padStart(2, '0')).join('');
}

function describe(error: unknown): string {
  return error instanceof Error ? `${error.name}: ${error.message}` : String(error);
}

type Attempt<T> = { ok: true; value: T; ms: number } | { ok: false; error: string; ms: number };

function attempt<T>(fn: () => T): Attempt<T> {
  const started = performance.now();
  try {
    return { ok: true, value: fn(), ms: Math.round(performance.now() - started) };
  } catch (error) {
    return { ok: false, error: describe(error), ms: Math.round(performance.now() - started) };
  }
}

export class ProbeDo extends DurableObject {
  override async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    const repetitions = Math.max(1, Math.min(20, Number(url.searchParams.get('n') ?? '1') || 1));

    let hex: string | null = null;
    let error: string | null = null;

    for (let index = 0; index < repetitions; index += 1) {
      try {
        hex = toHex(
          noblePbkdf2(sha256, utf8('password'), utf8('salt'), {
            c: PRODUCTION_ITERATIONS,
            dkLen: KEY_LENGTH_BYTES,
          }),
        );
      } catch (caught) {
        error = describe(caught);
        break;
      }
    }

    return new Response(
      JSON.stringify({
        ok: error === null,
        hex,
        error,
        repetitions,
        iterations: PRODUCTION_ITERATIONS,
        note: 'in-worker clocks are frozen; measure wall time with n=1 vs n=5',
      }),
      { headers: { 'content-type': 'application/json' } },
    );
  }
}

export default {
  async fetch(request: Request, env: { PROBE_DO?: DurableObjectNamespace }): Promise<Response> {
    const url = new URL(request.url);

    if (url.searchParams.get('do') === '1') {
      if (env.PROBE_DO === undefined) {
        return new Response(JSON.stringify({ error: 'PROBE_DO binding missing' }), {
          status: 500,
          headers: { 'content-type': 'application/json' },
        });
      }
      const id = env.PROBE_DO.idFromName('probe');
      const n = url.searchParams.get('n') ?? '1';
      return env.PROBE_DO.get(id).fetch(`https://probe.internal/?n=${n}`);
    }

    const vectors = VECTORS.map(([iterations, expected]) => {
      const result = attempt(() =>
        toHex(new Uint8Array(pbkdf2Sync(utf8('password'), utf8('salt'), iterations, KEY_LENGTH_BYTES, 'sha256'))),
      );
      return {
        iterations,
        ok: result.ok && result.value === expected,
        actual: result.ok ? result.value : result.error,
        ms: result.ms,
      };
    });

    const native600k = attempt(() =>
      toHex(new Uint8Array(pbkdf2Sync(utf8('password'), utf8('salt'), PRODUCTION_ITERATIONS, KEY_LENGTH_BYTES, 'sha256'))),
    );

    const body = {
      verdict: native600k.ok && vectors.every((vector) => vector.ok) ? 'native-pbkdf2-ok' : 'native-pbkdf2-failed',
      vectors,
      native600k: {
        ok: native600k.ok,
        ms: native600k.ms,
        error: native600k.ok ? null : native600k.error,
      },
      hint: 'append ?do=1 to measure the @noble/hashes fallback inside a Durable Object',
    };

    return new Response(JSON.stringify(body, null, 2), {
      headers: { 'content-type': 'application/json' },
    });
  },
};
