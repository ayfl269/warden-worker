import { describe, expect, it } from 'vitest';
import {
  optionalInt,
  parsePasswordGrant,
  REQUIRED_SCOPE,
  requiredField,
} from '../../src/auth/tokenRequest';
import { AppError } from '../../src/errors';

function params(values: Record<string, string>): URLSearchParams {
  return new URLSearchParams(values);
}

const VALID = {
  username: 'user@example.com',
  password: 'hash',
  scope: REQUIRED_SCOPE,
  client_id: 'web',
  device_identifier: 'device-1',
  device_name: 'My Device',
  device_type: '9',
};

function expectError(fn: () => unknown, message: string): void {
  try {
    fn();
  } catch (error) {
    expect(error).toBeInstanceOf(AppError);
    expect((error as AppError).status).toBe(400);
    expect((error as AppError).body).toBe(JSON.stringify({ error: message }));
    return;
  }
  throw new Error('expected AppError');
}

describe('requiredField', () => {
  it('trims and returns values', () => {
    expect(requiredField('  x  ', 'username')).toBe('x');
  });

  it('rejects missing or blank values with the field name', () => {
    expectError(() => requiredField(undefined, 'username'), 'Missing username');
    expectError(() => requiredField('   ', 'password'), 'Missing password');
  });
});

describe('optionalInt', () => {
  it('parses trimmed integers', () => {
    expect(optionalInt('0 ')).toBe(0);
    expect(optionalInt(' 1')).toBe(1);
  });

  it('returns undefined for absent or invalid values', () => {
    expect(optionalInt(undefined)).toBeUndefined();
    expect(optionalInt('abc')).toBeUndefined();
    expect(optionalInt('1.5')).toBeUndefined();
  });
});

describe('parsePasswordGrant', () => {
  it('accepts the camelCase device fields real clients send', () => {
    const parsed = parsePasswordGrant(
      params({
        username: 'user@example.com',
        password: 'hash',
        scope: REQUIRED_SCOPE,
        client_id: 'web',
        deviceIdentifier: 'device-1',
        deviceName: 'My Device',
        deviceType: '9',
      }),
    );
    expect(parsed.device).toEqual({ identifier: 'device-1', name: 'My Device', type: 9 });
  });

  it('parses a valid request', () => {
    const parsed = parsePasswordGrant(params(VALID));
    expect(parsed.username).toBe('user@example.com');
    expect(parsed.clientId).toBe('web');
    expect(parsed.device).toEqual({ identifier: 'device-1', name: 'My Device', type: 9 });
    expect(parsed.twoFactorProvider).toBeUndefined();
    expect(parsed.authRequest).toBeUndefined();
  });

  it('accepts a named device_type such as iOS', () => {
    const parsed = parsePasswordGrant(params({ ...VALID, device_type: 'iOS' }));
    expect(parsed.device.type).toBe(1);
  });

  it('trims the 2FA fields (Android sends a trailing space)', () => {
    const parsed = parsePasswordGrant(
      params({
        ...VALID,
        twoFactorProvider: '0 ',
        twoFactorToken: '123456',
        twoFactorRemember: '1',
      }),
    );
    expect(parsed.twoFactorProvider).toBe(0);
    expect(parsed.twoFactorToken).toBe('123456');
    expect(parsed.twoFactorRemember).toBe(1);
  });

  it('detects both authrequest spellings', () => {
    expect(parsePasswordGrant(params({ ...VALID, authrequest: 'r1' })).authRequest).toBe('r1');
    expect(parsePasswordGrant(params({ ...VALID, authRequest: 'r2' })).authRequest).toBe('r2');
  });

  it('requires an exact scope', () => {
    expectError(
      () => parsePasswordGrant(params({ ...VALID, scope: 'api' })),
      'Unsupported scope: api',
    );
    expectError(() => parsePasswordGrant(params({ ...VALID, scope: '' })), 'Missing scope');
  });

  it('requires every device field', () => {
    expectError(
      () => parsePasswordGrant(params({ ...VALID, device_identifier: '' })),
      'Missing device_identifier',
    );
    expectError(
      () => parsePasswordGrant(params({ ...VALID, device_name: ' ' })),
      'Missing device_name',
    );
    expectError(() => parsePasswordGrant(params({ ...VALID, client_id: '' })), 'Missing client_id');
  });

  it('rejects missing and unknown device types', () => {
    expectError(
      () => parsePasswordGrant(params({ ...VALID, device_type: '' })),
      'Missing device_type',
    );
    expectError(
      () => parsePasswordGrant(params({ ...VALID, device_type: 'toaster' })),
      'Invalid device_type',
    );
  });
});
