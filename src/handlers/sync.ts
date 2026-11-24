import type { Context } from 'hono';
import { z } from 'zod';

import { getDb } from '../db/client';
import { readJson } from '../http/body';
import { jsonResponse } from '../http/rawJson';
import { buildCipherResponse, type CipherRow } from '../models/cipherResponse';
import { buildDomainsPayload } from '../models/domains';
import { buildProfile } from '../models/profile';
import type { UserRow } from '../models/user';
import type { AppEnv } from '../types';

const syncQuerySchema = z.object({ excludeDomains: z.string().nullish() });

interface FolderRow {
  id: string;
  name: string;
  updated_at: string;
}

/** `GET /api/sync` */
export async function getSyncDataHandler(c: Context<AppEnv>): Promise<Response> {
  const db = getDb(c.env);
  const userId = c.get('claims').sub;

  const user = await db.prepare('SELECT * FROM users WHERE id = ?1').bind(userId).first<UserRow>();
  if (user === null) {
    return jsonResponse({ error: 'User not found' });
  }

  const twoFactor = await db
    .prepare(
      'SELECT COUNT(*) AS c FROM twofactor WHERE user_uuid = ?1 AND enabled = 1 AND atype = 0',
    )
    .bind(userId)
    .first<{ c: number }>();
  const twoFactorEnabled = (twoFactor?.c ?? 0) > 0;

  const folders = await db
    .prepare('SELECT id, name, updated_at FROM folders WHERE user_id = ?1')
    .bind(userId)
    .all<FolderRow>();

  const ciphers = await db
    .prepare('SELECT * FROM ciphers WHERE user_id = ?1')
    .bind(userId)
    .all<CipherRow>();

  const excludeDomains = (c.req.query('excludeDomains') ?? '').toLowerCase() === 'true';
  const domains = excludeDomains ? null : await buildDomainsPayload(db, user, false);

  const masterPasswordUnlock =
    user.master_password_hash.length > 0
      ? {
          kdf: {
            kdfType: user.kdf_type,
            iterations: user.kdf_iterations,
            memory: user.kdf_memory,
            parallelism: user.kdf_parallelism,
          },
          masterKeyEncryptedUserKey: user.key,
          masterKeyWrappedUserKey: user.key,
          salt: user.email,
        }
      : null;

  const body = {
    profile: buildProfile(user, twoFactorEnabled),
    folders: (folders.results ?? []).map((folder) => ({
      id: folder.id,
      name: folder.name,
      revisionDate: folder.updated_at,
      object: 'folder',
    })),
    collections: [],
    policies: [],
    ciphers: (ciphers.results ?? []).map((row) => buildCipherResponse(row)),
    domains,
    sends: [],
    userDecryption: { masterPasswordUnlock },
    object: 'sync',
  };

  return jsonResponse(body);
}

/** `GET /api/settings/domains` */
export async function getDomainsHandler(c: Context<AppEnv>): Promise<Response> {
  const db = getDb(c.env);
  const user = await db
    .prepare('SELECT equivalent_domains, excluded_globals FROM users WHERE id = ?1')
    .bind(c.get('claims').sub)
    .first<UserRow>();

  if (user === null) {
    return jsonResponse({ error: 'User not found' }, 404);
  }

  return jsonResponse(await buildDomainsPayload(db, user, true));
}

const updateDomainsSchema = z.object({
  equivalentDomains: z.array(z.array(z.string())).nullish(),
  excludedGlobalEquivalentDomains: z.array(z.number()).nullish(),
});

async function updateDomains(c: Context<AppEnv>): Promise<Response> {
  const payload = await readJson(c.req.raw, updateDomainsSchema);
  const db = getDb(c.env);

  const user = await db
    .prepare('SELECT equivalent_domains, excluded_globals FROM users WHERE id = ?1')
    .bind(c.get('claims').sub)
    .first<UserRow>();
  if (user === null) {
    return jsonResponse({ error: 'User not found' }, 404);
  }

  const equivalent =
    payload.equivalentDomains === undefined || payload.equivalentDomains === null
      ? user.equivalent_domains
      : JSON.stringify(payload.equivalentDomains);
  const excluded =
    payload.excludedGlobalEquivalentDomains === undefined ||
    payload.excludedGlobalEquivalentDomains === null
      ? user.excluded_globals
      : JSON.stringify(payload.excludedGlobalEquivalentDomains);

  await db
    .prepare(
      'UPDATE users SET equivalent_domains = ?1, excluded_globals = ?2, updated_at = ?3 WHERE id = ?4',
    )
    .bind(equivalent, excluded, new Date().toISOString(), c.get('claims').sub)
    .run();

  return jsonResponse({});
}

/** `POST /api/settings/domains` */
export async function postDomainsHandler(c: Context<AppEnv>): Promise<Response> {
  return updateDomains(c);
}

/** `PUT /api/settings/domains` */
export async function putDomainsHandler(c: Context<AppEnv>): Promise<Response> {
  return updateDomains(c);
}
