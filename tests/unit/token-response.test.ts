import { describe, expect, it } from 'vitest';

import {
  buildSendAccessTokenResponse,
  buildTokenResponse,
  TOKEN_EXPIRES_IN,
  TOKEN_SCOPE,
  type TokenResponseInput,
} from '../../src/models/tokenResponse';

function input(overrides: Partial<TokenResponseInput> = {}): TokenResponseInput {
  return {
    accessToken: 'access',
    refreshToken: 'refresh',
    userKey: 'user-key',
    privateKey: 'private-key',
    publicKey: 'public-key',
    kdfType: 0,
    kdfIterations: 600_000,
    kdfMemory: null,
    kdfParallelism: null,
    email: 'user@example.com',
    hasMasterPassword: true,
    ...overrides,
  };
}

describe('buildTokenResponse', () => {
  it('keeps the exact outer key order and casing', () => {
    const body = buildTokenResponse(input());
    expect(Object.keys(body)).toEqual([
      'access_token',
      'expires_in',
      'token_type',
      'refresh_token',
      'scope',
      'Key',
      'PrivateKey',
      'Kdf',
      'KdfIterations',
      'KdfMemory',
      'KdfParallelism',
      'ResetMasterPassword',
      'ForcePasswordReset',
      'UserDecryptionOptions',
      'AccountKeys',
    ]);
  });

  it('uses the documented constants', () => {
    const body = buildTokenResponse(input());
    expect(body.expires_in).toBe(TOKEN_EXPIRES_IN);
    expect(body.token_type).toBe('Bearer');
    expect(body.scope).toBe(TOKEN_SCOPE);
    expect(body.ResetMasterPassword).toBe(false);
    expect(body.ForcePasswordReset).toBe(false);
  });

  it('nests PascalCase userDecryptionOptions with a camelCase unlock payload', () => {
    const body = buildTokenResponse(input());
    const options = body.UserDecryptionOptions as Record<string, unknown>;
    expect(options.HasMasterPassword).toBe(true);
    expect(options.Object).toBe('userDecryptionOptions');

    const unlock = options.MasterPasswordUnlock as Record<string, unknown>;
    expect(Object.keys(unlock)).toEqual([
      'Kdf',
      'MasterKeyEncryptedUserKey',
      'MasterKeyWrappedUserKey',
      'Salt',
    ]);
    expect(unlock.Salt).toBe('user@example.com');
    expect(unlock.Kdf).toEqual({
      KdfType: 0,
      Iterations: 600_000,
      Memory: null,
      Parallelism: null,
    });
  });

  it('omits MasterPasswordUnlock when there is no master password', () => {
    const body = buildTokenResponse(input({ hasMasterPassword: false }));
    const options = body.UserDecryptionOptions as Record<string, unknown>;
    expect(options.HasMasterPassword).toBe(false);
    expect('MasterPasswordUnlock' in options).toBe(false);
  });

  it('omits TwoFactorToken when absent and includes it when present', () => {
    expect('TwoFactorToken' in buildTokenResponse(input())).toBe(false);
    expect(buildTokenResponse(input({ twoFactorToken: 't' })).TwoFactorToken).toBe('t');
  });

  it('builds the account keys envelope', () => {
    const keys = buildTokenResponse(input()).AccountKeys;
    expect(keys.Object).toBe('privateKeys');
    expect(keys.publicKeyEncryptionKeyPair).toEqual({
      wrappedPrivateKey: 'private-key',
      publicKey: 'public-key',
      Object: 'publicKeyEncryptionKeyPair',
    });
  });
});

describe('buildSendAccessTokenResponse', () => {
  it('uses snake_case and a 120s expiry', () => {
    expect(buildSendAccessTokenResponse('t')).toEqual({
      access_token: 't',
      expires_in: 120,
      token_type: 'Bearer',
      scope: 'api.send.access',
    });
  });
});
