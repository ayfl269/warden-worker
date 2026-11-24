import { describe, expect, it } from 'vitest';

import { nowString } from '../../src/db/client';

describe('nowString', () => {
  it('emits the Rust timestamp format (millis + Z, no offset)', () => {
    const value = nowString();
    expect(value).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/);
  });

  it('round-trips through Date without losing precision', () => {
    const value = nowString();
    expect(new Date(value).toISOString()).toBe(value);
  });

  it('is lexicographically sortable (string comparisons are used in SQL)', () => {
    const earlier = '2026-01-02T03:04:05.006Z';
    const later = '2026-01-02T03:04:05.007Z';
    expect(earlier < later).toBe(true);
    expect(new Date(earlier).getTime()).toBeLessThan(new Date(later).getTime());
  });
});
