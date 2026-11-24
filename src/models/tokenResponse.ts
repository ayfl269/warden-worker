/**
 * `POST /identity/connect/token` response body.
 *
 * The casing here is deliberately inconsistent (a Bitwarden client contract):
 * the outer envelope is snake_case, `UserDecryptionOptions` is PascalCase, and
 * `AccountKeys` / `MasterPasswordUnlock` are camelCase.
 */

export const TOKEN_SCOPE = 'api offline_access';
export const TOKEN_EXPIRES_IN = 3600;

export interface TokenResponseInput {
  accessToken: string;
  refreshToken: string;
  userKey: string;
  privateKey: string;
  publicKey: string;
  kdfType: number;
  kdfIterations: number;
  kdfMemory: number | null;
  kdfParallelism: number | null;
  email: string;
  /** False for accounts without a master password (passwordless). */
  hasMasterPassword: boolean;
  twoFactorToken?: string;
}

export interface TokenResponseBody {
  access_token: string;
  expires_in: number;
  token_type: string;
  refresh_token: string;
  scope: string;
  Key: string;
  PrivateKey: string;
  Kdf: number;
  KdfIterations: number;
  KdfMemory: number | null;
  KdfParallelism: number | null;
  ResetMasterPassword: boolean;
  ForcePasswordReset: boolean;
  UserDecryptionOptions: Record<string, unknown>;
  AccountKeys: Record<string, unknown>;
  TwoFactorToken?: string;
}

export function buildTokenResponse(input: TokenResponseInput): TokenResponseBody {
  const userDecryptionOptions: Record<string, unknown> = {
    HasMasterPassword: input.hasMasterPassword,
  };

  if (input.hasMasterPassword) {
    userDecryptionOptions.MasterPasswordUnlock = {
      Kdf: {
        KdfType: input.kdfType,
        Iterations: input.kdfIterations,
        Memory: input.kdfMemory,
        Parallelism: input.kdfParallelism,
      },
      MasterKeyEncryptedUserKey: input.userKey,
      MasterKeyWrappedUserKey: input.userKey,
      Salt: input.email,
    };
  }

  userDecryptionOptions.Object = 'userDecryptionOptions';

  const body: TokenResponseBody = {
    access_token: input.accessToken,
    expires_in: TOKEN_EXPIRES_IN,
    token_type: 'Bearer',
    refresh_token: input.refreshToken,
    scope: TOKEN_SCOPE,
    Key: input.userKey,
    PrivateKey: input.privateKey,
    Kdf: input.kdfType,
    KdfIterations: input.kdfIterations,
    KdfMemory: input.kdfMemory,
    KdfParallelism: input.kdfParallelism,
    ResetMasterPassword: false,
    ForcePasswordReset: false,
    UserDecryptionOptions: userDecryptionOptions,
    AccountKeys: {
      publicKeyEncryptionKeyPair: {
        wrappedPrivateKey: input.privateKey,
        publicKey: input.publicKey,
        Object: 'publicKeyEncryptionKeyPair',
      },
      Object: 'privateKeys',
    },
  };

  // Omitted entirely when absent — not serialized as null.
  if (input.twoFactorToken !== undefined) {
    body.TwoFactorToken = input.twoFactorToken;
  }

  return body;
}

/** `grant_type=send_access` response (snake_case, no renames). */
export function buildSendAccessTokenResponse(accessToken: string): Record<string, unknown> {
  return {
    access_token: accessToken,
    expires_in: 120,
    token_type: 'Bearer',
    scope: 'api.send.access',
  };
}
