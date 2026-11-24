import { AppError } from '../errors';
import type { UserRow } from './user';

/**
 * `Profile` payload shared by `/api/accounts/profile`, `/api/accounts/avatar`
 * and `/api/sync`. Mirrors `models/sync.rs::Profile` field for field.
 */
export interface Profile {
  name?: string;
  avatarColor: string | null;
  email: string;
  id: string;
  securityStamp: string;
  object: string;
  premiumFromOrganization: boolean;
  culture: string;
  forcePasswordReset: boolean;
  emailVerified: boolean;
  twoFactorEnabled: boolean;
  premium: boolean;
  usesKeyConnector: boolean;
  creationDate: string;
  privateKey: string;
  key: string;
  accountKeys: Record<string, unknown>;
  organizations: unknown[];
  providers: unknown[];
  providerOrganizations: unknown[];
  _status: number;
}

/** `created_at` (millisecond precision) → RFC3339 with microseconds. */
export function toMicrosTimestamp(value: string): string {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    throw AppError.internal();
  }
  return date.toISOString().replace(/Z$/, '000Z');
}

export function buildProfile(user: UserRow, twoFactorEnabled: boolean): Profile {
  const profile: Profile = {
    avatarColor: user.avatar_color,
    email: user.email,
    id: user.id,
    securityStamp: user.security_stamp ?? '',
    object: 'profile',
    premiumFromOrganization: false,
    culture: 'en-US',
    forcePasswordReset: false,
    emailVerified: true,
    twoFactorEnabled,
    premium: true,
    usesKeyConnector: false,
    creationDate: toMicrosTimestamp(user.created_at),
    privateKey: user.private_key,
    key: user.key,
    accountKeys: {
      publicKeyEncryptionKeyPair: {
        wrappedPrivateKey: user.private_key,
        publicKey: user.public_key,
        signedPublicKey: null,
        object: 'publicKeyEncryptionKeyPair',
      },
      securityState: null,
      signatureKeyPair: null,
      object: 'privateKeys',
    },
    organizations: [],
    providers: [],
    providerOrganizations: [],
    _status: 0,
  };

  // Omitted entirely when the user has no display name.
  if (user.name !== null) {
    profile.name = user.name;
  }

  return profile;
}
