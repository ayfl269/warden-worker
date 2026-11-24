/**
 * Runtime bindings and environment-variable readers.
 *
 * Mirrors `src/handlers/mod.rs` + `src/lib.rs` so that defaults, clamping and
 * warning behaviour stay identical to the Rust implementation.
 */

/** Minimum PBKDF2 iterations for server-side password hashing (`crypto.rs`). */
export const MIN_SERVER_PBKDF2_ITERATIONS = 600_000;

/** axum `DefaultBodyLimit` used by the main worker and HeavyDo. */
export const MAX_BODY_BYTES = 5 * 1024 * 1024;

export type Env = {
  readonly vault1: D1Database;
  readonly ATTACHMENTS_KV?: KVNamespace;
  readonly ATTACHMENTS_BUCKET?: R2Bucket;
  readonly HEAVY_DO?: DurableObjectNamespace;
  readonly NOTIFY_DO?: DurableObjectNamespace;
  readonly LOGIN_RATE_LIMITER?: RateLimit;
  readonly SEND_ACCESS_RATE_LIMITER?: RateLimit;

  // Secrets
  readonly JWT_SECRET?: string;
  readonly JWT_REFRESH_SECRET?: string;
  readonly ALLOWED_EMAILS?: string;
  readonly PUSH_INSTALLATION_ID?: string;
  readonly PUSH_INSTALLATION_KEY?: string;

  // Vars
  readonly BASE_URL?: string;
  readonly PASSWORD_ITERATIONS?: string;
  readonly LOGIN_MISSING_USER_DELAY_MS?: string;
  readonly IMPORT_BATCH_SIZE?: string;
  readonly CIPHERS_DEFAULT_ROW_QUERY?: string;
  readonly SYNC_RESPONSE_PREALLOC_BYTES?: string;
  readonly PUSH_ENABLED?: string;
  readonly PUSH_RELAY_URI?: string;
  readonly PUSH_IDENTITY_URI?: string;
  readonly TRASH_AUTO_DELETE_DAYS?: string;
  readonly ATTACHMENT_MAX_BYTES?: string;
  readonly ATTACHMENT_TOTAL_LIMIT_KB?: string;
  readonly ATTACHMENT_TTL_SECS?: string;
  readonly SEND_TEXT_MAX_BYTES?: string;
  readonly SEND_MAX_BYTES?: string;
  readonly USER_SEND_LIMIT_KB?: string;
  readonly SEND_TTL_SECS?: string;
  readonly DISABLE_USER_REGISTRATION?: string;
  readonly AUTHENTICATOR_DISABLE_TIME_DRIFT?: string;
  /** Return password hints in the response body (default: off, hint is not exposed). */
  readonly EXPOSE_PASSWORD_HINTS?: string;
};

/** Strict `usize` parser: rejects negatives, decimals and trailing garbage. */
function parseUsize(raw: string | undefined): number | undefined {
  if (raw === undefined) return undefined;
  const trimmed = raw.trim();
  if (!/^\d+$/.test(trimmed)) return undefined;
  const parsed = Number(trimmed);
  return Number.isSafeInteger(parsed) ? parsed : undefined;
}

function isTruthyFlag(raw: string | undefined): boolean {
  return raw !== undefined && /^(1|true|yes|on)$/i.test(raw.trim().toLowerCase());
}

export function getEnvUsize(env: Env, name: keyof Env, fallback: number): number {
  const raw = env[name];
  return (typeof raw === 'string' ? parseUsize(raw) : undefined) ?? fallback;
}

/**
 * Per-user server-side PBKDF2 iterations.
 *
 * Defaults to 600k; values below the minimum (or unparsable) are clamped up,
 * exactly like `server_password_iterations()`.
 */
export function serverPasswordIterations(env: Env): number {
  const raw = env.PASSWORD_ITERATIONS;
  if (raw === undefined) return MIN_SERVER_PBKDF2_ITERATIONS;

  const parsed = parseUsize(raw);
  if (parsed === undefined) {
    console.warn(
      `Invalid PASSWORD_ITERATIONS='${raw}'; using minimum ${MIN_SERVER_PBKDF2_ITERATIONS}`,
    );
    return MIN_SERVER_PBKDF2_ITERATIONS;
  }
  if (parsed < MIN_SERVER_PBKDF2_ITERATIONS) {
    console.warn(
      `PASSWORD_ITERATIONS=${parsed} is below the minimum ${MIN_SERVER_PBKDF2_ITERATIONS}; clamping to ${MIN_SERVER_PBKDF2_ITERATIONS}`,
    );
    return MIN_SERVER_PBKDF2_ITERATIONS;
  }
  return parsed;
}

/** Whether TOTP validation allows ±1 time step drift (default: enabled). */
export function allowTotpDrift(env: Env): boolean {
  return !isTruthyFlag(env.AUTHENTICATOR_DISABLE_TIME_DRIFT);
}

/** Prefer per-row cipher JSON fetching (avoids `SQLITE_TOOBIG` on large vaults). */
export function ciphersDefaultRowQuery(env: Env): boolean {
  return isTruthyFlag(env.CIPHERS_DEFAULT_ROW_QUERY);
}

/** Optional `/api/sync` response capacity hint, in bytes. */
export function syncResponsePreallocBytes(env: Env): number | undefined {
  const raw = env.SYNC_RESPONSE_PREALLOC_BYTES;
  if (raw === undefined) return undefined;
  const parsed = parseUsize(raw);
  if (parsed === undefined) {
    console.warn(`Invalid SYNC_RESPONSE_PREALLOC_BYTES='${raw}'; ignoring`);
  }
  return parsed;
}

/**
 * Whether the client UI should hide the registration button.
 * Defaults to true; only the literal value `false` turns it off.
 */
export function disableUserRegistration(env: Env): boolean {
  return env.DISABLE_USER_REGISTRATION?.toLowerCase() !== 'false';
}
