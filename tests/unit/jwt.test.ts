import { describe, expect, it } from 'vitest';
import type { AccessClaims } from '../../src/auth/jwt';
import {
  ACCESS_TOKEN_TTL_SECONDS,
  isSessionStillValid,
  jwtSecret,
  parseBearer,
  SEND_ACCESS_ISSUER,
  signToken,
  verifyAccessToken,
  verifyToken,
} from '../../src/auth/jwt';
import type { Env } from '../../src/env';

const SECRET = 'test-jwt-secret';

function envWith(values: Partial<Env>): Env {
  return values as Env;
}

function accessPayload(overrides: Partial<AccessClaims> = {}): Record<string, unknown> {
  return {
    sub: 'user-1',
    sstamp: 'stamp-1',
    premium: true,
    name: 'User',
    email: 'user@example.com',
    email_verified: false,
    device: 'device-1',
    devicetype: 'Chrome',
    client_id: 'web',
    scope: ['api', 'offline_access'],
    amr: ['Application'],
    ...overrides,
  };
}

describe('signToken / verifyToken', () => {
  it('round-trips an access token with the exact claim names', async () => {
    const token = await signToken(accessPayload(), SECRET, ACCESS_TOKEN_TTL_SECONDS);
    const claims = await verifyAccessToken(envWith({ JWT_SECRET: SECRET }), token);

    expect(claims).not.toBeNull();
    expect(claims?.sub).toBe('user-1');
    expect(claims?.sstamp).toBe('stamp-1');
    expect(claims?.email_verified).toBe(false);
    expect(claims?.scope).toEqual(['api', 'offline_access']);
    expect(claims?.amr).toEqual(['Application']);
    expect(typeof claims?.exp).toBe('number');
  });

  it('rejects a token signed with another secret', async () => {
    const token = await signToken(accessPayload(), 'other-secret', 60);
    expect(await verifyToken(token, SECRET)).toBeNull();
  });

  it('rejects a tampered payload', async () => {
    const token = await signToken(accessPayload(), SECRET, 60);
    const [header, , signature] = token.split('.');
    const forged = `${header}.${btoa(JSON.stringify({ sub: 'attacker' })).replace(/=+$/, '')}.${signature}`;
    expect(await verifyToken(forged, SECRET)).toBeNull();
  });

  it('rejects an expired token beyond the leeway', async () => {
    const token = await signToken(accessPayload(), SECRET, -120);
    expect(await verifyToken(token, SECRET)).toBeNull();
  });

  it('accepts a token that expired inside the 60s leeway', async () => {
    const token = await signToken(accessPayload(), SECRET, -30);
    expect(await verifyToken(token, SECRET)).not.toBeNull();
  });

  it('enforces the issuer when requested', async () => {
    const token = await signToken({ sub: 'send-1', iss: SEND_ACCESS_ISSUER }, SECRET, 120);
    expect(await verifyToken(token, SECRET, { issuer: SEND_ACCESS_ISSUER })).not.toBeNull();
    expect(await verifyToken(token, SECRET, { issuer: 'someone-else' })).toBeNull();
  });

  it('expires attachment tokens 60s before their TTL', async () => {
    const ttl = 300;
    const token = await signToken(
      { sub: 'u', cipher_id: 'c', attachment_id: 'a' },
      SECRET,
      ttl - 60,
    );
    const claims = await verifyToken<{ iat: number; exp: number }>(token, SECRET);
    expect(claims).not.toBeNull();
    expect((claims?.exp ?? 0) - (claims?.iat ?? 0)).toBe(ttl - 60);
  });
});

describe('verifyAccessToken', () => {
  it('rejects tokens missing required claims', async () => {
    const env = envWith({ JWT_SECRET: SECRET });
    const token = await signToken({ sub: 'user-1', sstamp: 'stamp-1' }, SECRET, 60);
    expect(await verifyAccessToken(env, token)).toBeNull();
  });

  it('throws a 500 when the secret is not configured', () => {
    expect(() => jwtSecret(envWith({}), 'JWT_SECRET')).toThrowError();
    try {
      jwtSecret(envWith({}), 'JWT_SECRET');
    } catch (error) {
      expect((error as { status?: number }).status).toBe(500);
    }
  });
});

describe('parseBearer', () => {
  it('requires the exact `Bearer ` prefix', () => {
    expect(parseBearer('Bearer abc')).toBe('abc');
    expect(parseBearer('bearer abc')).toBeNull();
    expect(parseBearer('Bearer  abc')).toBe(' abc');
    expect(parseBearer('Token abc')).toBeNull();
    expect(parseBearer('Bearer ')).toBeNull();
    expect(parseBearer(undefined)).toBeNull();
  });
});

describe('isSessionStillValid', () => {
  function fakeDb(user: { security_stamp: string | null } | null, hasDevice: boolean) {
    return {
      prepare(query: string) {
        const statement = {
          bind() {
            return statement;
          },
          async first() {
            return query.includes('FROM users') ? user : hasDevice ? { identifier: 'd' } : null;
          },
        };
        return statement as unknown as D1PreparedStatement;
      },
    };
  }

  const claims = {
    ...(accessPayload() as unknown as AccessClaims),
    exp: 0,
    iat: 0,
    nbf: 0,
  };

  it('accepts a matching stamp with an existing device', async () => {
    expect(await isSessionStillValid(fakeDb({ security_stamp: 'stamp-1' }, true), claims)).toBe(
      true,
    );
  });

  it('rejects a rotated stamp', async () => {
    expect(await isSessionStillValid(fakeDb({ security_stamp: 'stamp-2' }, true), claims)).toBe(
      false,
    );
  });

  it('rejects a missing user or device', async () => {
    expect(await isSessionStillValid(fakeDb(null, true), claims)).toBe(false);
    expect(await isSessionStillValid(fakeDb({ security_stamp: 'stamp-1' }, false), claims)).toBe(
      false,
    );
  });

  it('rejects a NULL stamp (constant-time comparison still applies)', async () => {
    expect(await isSessionStillValid(fakeDb({ security_stamp: null }, true), claims)).toBe(false);
  });
});
