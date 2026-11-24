import type { Db } from '../db/client';

interface UserDomains {
  equivalent_domains: string;
  excluded_globals: string;
}

interface GlobalDomainRow {
  type: number;
  domains_json: string;
  sort_order: number;
}

function parseJson(value: string, fallback: unknown): unknown {
  try {
    return JSON.parse(value);
  } catch {
    return fallback;
  }
}

/**
 * Build the `domains` payload shared by `/api/sync` and `/api/settings/domains`.
 *
 * `includeExcluded` is true for the settings endpoint (every group is returned
 * with an `excluded` flag) and false for sync (excluded groups are filtered out).
 */
export async function buildDomainsPayload(
  db: Db,
  user: UserDomains,
  includeExcluded: boolean,
): Promise<Record<string, unknown>> {
  const equivalentDomains = parseJson(user.equivalent_domains, []);
  const excluded = new Set(
    (parseJson(user.excluded_globals, []) as unknown[]).filter(
      (value): value is number => typeof value === 'number',
    ),
  );

  const rows = await db
    .prepare(
      'SELECT type, domains_json, sort_order FROM global_equivalent_domains ORDER BY sort_order',
    )
    .all<GlobalDomainRow>();

  const globalEquivalentDomains: Array<Record<string, unknown>> = [];
  for (const row of rows.results ?? []) {
    const isExcluded = excluded.has(row.type);
    if (!includeExcluded && isExcluded) continue;
    globalEquivalentDomains.push({
      type: row.type,
      domains: parseJson(row.domains_json, []),
      excluded: isExcluded,
    });
  }

  return { equivalentDomains, globalEquivalentDomains, object: 'domains' };
}
