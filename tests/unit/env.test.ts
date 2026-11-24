import { describe, expect, it } from 'vitest';

import type { Env } from '../../src/env';
import {
  allowTotpDrift,
  ciphersDefaultRowQuery,
  disableUserRegistration,
  getEnvUsize,
  MIN_SERVER_PBKDF2_ITERATIONS,
  serverPasswordIterations,
  syncResponsePreallocBytes,
} from '../../src/env';

function envWith(values: Partial<Env>): Env {
  return values as Env;
}

describe('serverPasswordIterations', () => {
  it('defaults to the 600k minimum', () => {
    expect(serverPasswordIterations(envWith({}))).toBe(MIN_SERVER_PBKDF2_ITERATIONS);
  });

  it('clamps values below the minimum up to it', () => {
    expect(serverPasswordIterations(envWith({ PASSWORD_ITERATIONS: '100000' }))).toBe(
      MIN_SERVER_PBKDF2_ITERATIONS,
    );
    expect(serverPasswordIterations(envWith({ PASSWORD_ITERATIONS: '0' }))).toBe(
      MIN_SERVER_PBKDF2_ITERATIONS,
    );
  });

  it('accepts higher values verbatim', () => {
    expect(serverPasswordIterations(envWith({ PASSWORD_ITERATIONS: '1200000' }))).toBe(1_200_000);
  });

  it('falls back to the minimum for unparsable input', () => {
    expect(serverPasswordIterations(envWith({ PASSWORD_ITERATIONS: 'lots' }))).toBe(
      MIN_SERVER_PBKDF2_ITERATIONS,
    );
    expect(serverPasswordIterations(envWith({ PASSWORD_ITERATIONS: '-5' }))).toBe(
      MIN_SERVER_PBKDF2_ITERATIONS,
    );
    expect(serverPasswordIterations(envWith({ PASSWORD_ITERATIONS: '1.5' }))).toBe(
      MIN_SERVER_PBKDF2_ITERATIONS,
    );
  });
});

describe('allowTotpDrift', () => {
  it('allows drift by default', () => {
    expect(allowTotpDrift(envWith({}))).toBe(true);
  });

  it('disables drift for truthy values', () => {
    for (const value of ['1', 'true', 'TRUE', 'yes', 'on']) {
      expect(allowTotpDrift(envWith({ AUTHENTICATOR_DISABLE_TIME_DRIFT: value }))).toBe(false);
    }
  });

  it('keeps drift for other values', () => {
    expect(allowTotpDrift(envWith({ AUTHENTICATOR_DISABLE_TIME_DRIFT: '0' }))).toBe(true);
    expect(allowTotpDrift(envWith({ AUTHENTICATOR_DISABLE_TIME_DRIFT: 'false' }))).toBe(true);
  });
});

describe('ciphersDefaultRowQuery', () => {
  it('defaults to false (aggregate query, then SQLITE_TOOBIG fallback)', () => {
    expect(ciphersDefaultRowQuery(envWith({}))).toBe(false);
  });

  it('accepts truthy flags', () => {
    expect(ciphersDefaultRowQuery(envWith({ CIPHERS_DEFAULT_ROW_QUERY: 'true' }))).toBe(true);
    expect(ciphersDefaultRowQuery(envWith({ CIPHERS_DEFAULT_ROW_QUERY: '1' }))).toBe(true);
  });
});

describe('disableUserRegistration', () => {
  it('defaults to true', () => {
    expect(disableUserRegistration(envWith({}))).toBe(true);
  });

  it('only the literal value false turns it off', () => {
    expect(disableUserRegistration(envWith({ DISABLE_USER_REGISTRATION: 'false' }))).toBe(false);
    expect(disableUserRegistration(envWith({ DISABLE_USER_REGISTRATION: 'FALSE' }))).toBe(false);
    expect(disableUserRegistration(envWith({ DISABLE_USER_REGISTRATION: '0' }))).toBe(true);
  });
});

describe('getEnvUsize', () => {
  it('parses unsigned integers and rejects the rest', () => {
    expect(getEnvUsize(envWith({ IMPORT_BATCH_SIZE: '30' }), 'IMPORT_BATCH_SIZE', 7)).toBe(30);
    expect(getEnvUsize(envWith({ IMPORT_BATCH_SIZE: '0' }), 'IMPORT_BATCH_SIZE', 7)).toBe(0);
    expect(getEnvUsize(envWith({ IMPORT_BATCH_SIZE: 'abc' }), 'IMPORT_BATCH_SIZE', 7)).toBe(7);
    expect(getEnvUsize(envWith({}), 'IMPORT_BATCH_SIZE', 7)).toBe(7);
  });
});

describe('syncResponsePreallocBytes', () => {
  it('returns undefined when unset or invalid', () => {
    expect(syncResponsePreallocBytes(envWith({}))).toBeUndefined();
    expect(
      syncResponsePreallocBytes(envWith({ SYNC_RESPONSE_PREALLOC_BYTES: 'big' })),
    ).toBeUndefined();
  });

  it('returns the parsed value including zero', () => {
    expect(syncResponsePreallocBytes(envWith({ SYNC_RESPONSE_PREALLOC_BYTES: '1048576' }))).toBe(
      1_048_576,
    );
    expect(syncResponsePreallocBytes(envWith({ SYNC_RESPONSE_PREALLOC_BYTES: '0' }))).toBe(0);
  });
});
