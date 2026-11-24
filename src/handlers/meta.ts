import { getDb, nowString } from '../db/client';
import type { Env } from '../env';
import { AppError } from '../errors';
import { jsonResponse } from '../http/rawJson';
import { SERVER_VERSION } from './config';

/** `GET /api/now` — RFC3339 timestamp with millisecond precision and `Z`. */
export function nowHandler(): Response {
  return jsonResponse(nowString());
}

/** `GET /api/version` — the emulated Bitwarden server version string. */
export function versionHandler(): Response {
  return jsonResponse(SERVER_VERSION);
}

/** `GET /api/alive` — verifies D1 connectivity, then returns the timestamp. */
export async function aliveHandler(env: Env): Promise<Response> {
  try {
    await getDb(env).prepare('SELECT 1 as ok').first();
  } catch {
    throw AppError.database();
  }
  return jsonResponse(nowString());
}

/** `GET /api/hibp/breach` — not supported; always an empty list. */
export function hibpBreachHandler(): Response {
  return jsonResponse([]);
}
