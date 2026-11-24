/**
 * Routes offloaded to `HEAVY_DO` (CPU-heavy flows).
 *
 * Kept in its own module (no `cloudflare:workers` imports) so it can be compared
 * against the Rust reference implementation in tests.
 */
export const HEAVY_DO_ROUTE_METHODS: ReadonlyMap<string, ReadonlySet<string>> = new Map([
  // Import
  ['/api/ciphers/import', new Set(['POST'])],

  // Identity / auth (password hashing / verification)
  ['/identity/accounts/register', new Set(['POST'])],
  ['/identity/accounts/register/finish', new Set(['POST'])],

  // Password / KDF changes
  ['/api/accounts/password', new Set(['POST'])],
  ['/api/accounts/kdf', new Set(['POST'])],

  // Dangerous operations requiring password verification
  ['/api/accounts/delete', new Set(['POST'])],
  ['/api/accounts', new Set(['DELETE'])],
  ['/api/ciphers/purge', new Set(['POST'])],

  // Security stamp rotation requires password verification
  ['/api/accounts/security-stamp', new Set(['POST'])],

  // Key rotation verifies the master password and rewrites the whole vault
  ['/api/accounts/key-management/rotate-user-account-keys', new Set(['POST'])],

  // Two-factor
  ['/api/two-factor/get-authenticator', new Set(['POST'])],
  ['/api/two-factor/authenticator', new Set(['POST', 'PUT', 'DELETE'])],
  ['/api/two-factor/disable', new Set(['POST', 'PUT'])],
  ['/api/two-factor/get-recover', new Set(['POST'])],
]);

/** Whether a normalized path + method should be forwarded to HeavyDo. */
export function shouldOffloadHeavy(pathname: string, method: string): boolean {
  const methods = HEAVY_DO_ROUTE_METHODS.get(pathname);
  return methods !== undefined && methods.has(method.toUpperCase());
}

/**
 * Whether the token endpoint should be offloaded.
 *
 * Only the plain password grant is CPU-heavy: `authrequest` logins skip the
 * master-password verification and `refresh_token` is a cheap HS256 check.
 */
export function shouldOffloadToken(grantType: string | null, authRequest: string | null): boolean {
  return grantType === 'password' && authRequest === null;
}
