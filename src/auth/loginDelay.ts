import type { Env } from '../env';

/** Default base delay for a non-existent login user (`LOGIN_MISSING_USER_DELAY_MS`). */
export const DEFAULT_MISSING_USER_DELAY_MS = 550;

/** Jitter range applied to the base delay: ±30ms. */
export const MISSING_USER_JITTER_MS = 30;

/**
 * Compute the delay for a missing user.
 *
 * Mirrors the Rust implementation exactly:
 * `base + (randomByte * 61 / 256 - 30)`, clamped at zero, using integer
 * arithmetic (`randomByte * 61 / 256` truncates).
 */
export function computeMissingUserDelay(baseMs: number, randomByte: number): number {
  const byte = randomByte & 0xff;
  const jitter = Math.trunc((byte * 61) / 256) - MISSING_USER_JITTER_MS;
  return Math.max(0, baseMs + jitter);
}

function randomByte(): number {
  const buffer = new Uint8Array(1);
  crypto.getRandomValues(buffer);
  return buffer[0] as number;
}

/** Base delay from env, defaulting to 550ms (negative values are allowed). */
export function missingUserBaseDelayMs(env: Env): number {
  const raw = env.LOGIN_MISSING_USER_DELAY_MS;
  if (raw === undefined) return DEFAULT_MISSING_USER_DELAY_MS;

  const trimmed = raw.trim();
  if (!/^-?\d+$/.test(trimmed)) return DEFAULT_MISSING_USER_DELAY_MS;

  const parsed = Number.parseInt(trimmed, 10);
  return Number.isSafeInteger(parsed) ? parsed : DEFAULT_MISSING_USER_DELAY_MS;
}

/** Delay to apply before returning `Invalid credentials` for an unknown user. */
export function missingUserDelayMs(env: Env): number {
  return computeMissingUserDelay(missingUserBaseDelayMs(env), randomByte());
}

/** Await a delay; split into chunks so long delays stay cancellable. */
export async function sleep(ms: number): Promise<void> {
  if (ms <= 0) return;
  await new Promise<void>((resolve) => {
    setTimeout(resolve, ms);
  });
}
