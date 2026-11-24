import { disableUserRegistration, type Env } from '../env';

/** Reported to clients; keep in sync with the supported Bitwarden server version. */
export const SERVER_VERSION = '2026.6.0';
export const GIT_HASH = '5d84f176';

/** `GET /api/config` — mirrors `handlers/config.rs` field for field. */
export function configHandler(env: Env, baseUrl: string): Response {
  const body = {
    version: SERVER_VERSION,
    gitHash: GIT_HASH,
    server: {
      name: 'Vaultwarden',
      url: 'https://github.com/dani-garcia/vaultwarden',
    },
    settings: {
      disableUserRegistration: disableUserRegistration(env),
      suppressOnboardingInterstitials: false,
    },
    environment: {
      vault: baseUrl,
      api: `${baseUrl}/api`,
      identity: `${baseUrl}/identity`,
      notifications: `${baseUrl}/notifications`,
      sso: '',
      cloudRegion: null,
    },
    push: {
      pushTechnology: 0,
      vapidPublicKey: null,
    },
    featureStates: {
      'pm-19051-send-email-verification': false,
      'pm-19148-innovation-archive': true,
      'cxp-import-mobile': true,
      'cxp-export-mobile': true,
    },
    communication: null,
    object: 'config',
  };

  return new Response(JSON.stringify(body), {
    headers: { 'content-type': 'application/json' },
  });
}
