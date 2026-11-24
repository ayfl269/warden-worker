import type { AccessClaims } from './auth/jwt';
import type { Env } from './env';

/** Hono context shape shared by the main worker and HeavyDo. */
export type AppEnv = {
  Bindings: Env;
  Variables: {
    /** Base URL used by `/api/config` and auth-request origins. */
    baseUrl: string;
    /** Populated by `requireAuth()`; absent on unauthenticated routes. */
    claims: AccessClaims;
  };
};
