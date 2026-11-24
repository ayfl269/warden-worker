import { AppError } from '../errors';
import { parseDeviceType } from './device';

/** Exact scope string required by the password grant. */
export const REQUIRED_SCOPE = 'api offline_access';

export interface DeviceRequest {
  identifier: string;
  name: string;
  type: number;
}

export interface ParsedPasswordGrant {
  username: string;
  password: string;
  scope: string;
  clientId: string;
  device: DeviceRequest;
  twoFactorProvider: number | undefined;
  twoFactorToken: string | undefined;
  twoFactorRemember: number | undefined;
  authRequest: string | undefined;
}

/** `required_field`: trims and rejects empty values with `Missing {name}`. */
export function requiredField(value: string | null | undefined, name: string): string {
  const trimmed = value?.trim() ?? '';
  if (trimmed.length === 0) {
    throw AppError.badRequest(`Missing ${name}`);
  }
  return trimmed;
}

/** Optional integer parsed with whitespace trimming (Android sends `"0 "`). */
export function optionalInt(value: string | null | undefined): number | undefined {
  if (value === undefined || value === null) return undefined;
  const trimmed = value.trim();
  if (!/^-?\d+$/.test(trimmed)) return undefined;
  const parsed = Number.parseInt(trimmed, 10);
  return Number.isSafeInteger(parsed) ? parsed : undefined;
}

/**
 * Parse an `application/x-www-form-urlencoded` password-grant body.
 *
 * Mirrors the Rust extractor order and messages: username, scope, client_id,
 * device_identifier, device_name, then a strict device_type.
 */
export function parsePasswordGrant(params: URLSearchParams): ParsedPasswordGrant {
  const username = requiredField(params.get('username'), 'username');
  const password = requiredField(params.get('password'), 'password');

  const rawScope = params.get('scope');
  if (rawScope === null || rawScope.trim().length === 0) {
    throw AppError.badRequest('Missing scope');
  }
  const scope = rawScope.trim();
  if (scope !== REQUIRED_SCOPE) {
    throw AppError.badRequest(`Unsupported scope: ${scope}`);
  }

  // Bitwarden clients send camelCase device fields; snake_case is accepted as a
  // fallback. `client_id` stays snake_case on the wire.
  const clientId = requiredField(params.get('client_id'), 'client_id');
  const identifier = requiredField(
    params.get('deviceIdentifier') ?? params.get('device_identifier'),
    'device_identifier',
  );
  const deviceName = requiredField(
    params.get('deviceName') ?? params.get('device_name'),
    'device_name',
  );

  const rawDeviceType = params.get('deviceType') ?? params.get('device_type');
  if (rawDeviceType === null || rawDeviceType.trim().length === 0) {
    throw AppError.badRequest('Missing device_type');
  }
  const deviceType = parseDeviceType(rawDeviceType);
  if (deviceType === null) {
    throw AppError.badRequest('Invalid device_type');
  }

  return {
    username,
    password,
    scope,
    clientId,
    device: { identifier, name: deviceName, type: deviceType },
    twoFactorProvider: optionalInt(params.get('twoFactorProvider')),
    twoFactorToken: params.get('twoFactorToken') ?? undefined,
    twoFactorRemember: optionalInt(params.get('twoFactorRemember')),
    authRequest: params.get('authrequest') ?? params.get('authRequest') ?? undefined,
  };
}
