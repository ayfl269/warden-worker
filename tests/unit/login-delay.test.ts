import { describe, expect, it } from 'vitest';
import {
  computeMissingUserDelay,
  DEFAULT_MISSING_USER_DELAY_MS,
  MISSING_USER_JITTER_MS,
  missingUserBaseDelayMs,
  missingUserDelayMs,
} from '../../src/auth/loginDelay';
import type { Env } from '../../src/env';

function envWith(values: Partial<Env>): Env {
  return values as Env;
}

describe('computeMissingUserDelay', () => {
  it('matches the Rust integer formula at the boundaries', () => {
    // byte 0   → 0 - 30   = -30 → 520
    expect(computeMissingUserDelay(550, 0)).toBe(520);
    // byte 128 → 30 - 30  = 0   → 550
    expect(computeMissingUserDelay(550, 128)).toBe(550);
    // byte 255 → 60 - 30  = +30 → 580
    expect(computeMissingUserDelay(550, 255)).toBe(580);
  });

  it('truncates the division instead of rounding', () => {
    // 1 * 61 / 256 = 0.238 → 0
    expect(computeMissingUserDelay(550, 1)).toBe(520);
    // 5 * 61 / 256 = 1.19 → 1
    expect(computeMissingUserDelay(550, 5)).toBe(521);
  });

  it('clamps at zero for negative bases', () => {
    expect(computeMissingUserDelay(-1000, 0)).toBe(0);
    expect(computeMissingUserDelay(0, 0)).toBe(0);
  });

  it('masks the random byte to 8 bits', () => {
    expect(computeMissingUserDelay(550, 256)).toBe(computeMissingUserDelay(550, 0));
  });
});

describe('missingUserBaseDelayMs', () => {
  it('defaults to 550ms', () => {
    expect(missingUserBaseDelayMs(envWith({}))).toBe(DEFAULT_MISSING_USER_DELAY_MS);
  });

  it('accepts overrides, including negatives', () => {
    expect(missingUserBaseDelayMs(envWith({ LOGIN_MISSING_USER_DELAY_MS: '900' }))).toBe(900);
    expect(missingUserBaseDelayMs(envWith({ LOGIN_MISSING_USER_DELAY_MS: '-50' }))).toBe(-50);
  });

  it('falls back for invalid values', () => {
    expect(missingUserBaseDelayMs(envWith({ LOGIN_MISSING_USER_DELAY_MS: 'slow' }))).toBe(
      DEFAULT_MISSING_USER_DELAY_MS,
    );
    expect(missingUserBaseDelayMs(envWith({ LOGIN_MISSING_USER_DELAY_MS: '1.5' }))).toBe(
      DEFAULT_MISSING_USER_DELAY_MS,
    );
  });
});

describe('missingUserDelayMs', () => {
  it('stays within the documented ±30ms band', () => {
    for (let index = 0; index < 50; index += 1) {
      const delay = missingUserDelayMs(envWith({}));
      expect(delay).toBeGreaterThanOrEqual(DEFAULT_MISSING_USER_DELAY_MS - MISSING_USER_JITTER_MS);
      expect(delay).toBeLessThanOrEqual(DEFAULT_MISSING_USER_DELAY_MS + MISSING_USER_JITTER_MS);
    }
  });
});
