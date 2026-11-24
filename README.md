# Warden: A Bitwarden-compatible server for Cloudflare Workers

[![Powered by Cloudflare](https://img.shields.io/badge/Powered%20by-Cloudflare-F38020?logo=cloudflare&logoColor=white)](https://www.cloudflare.com/)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Deploy to Cloudflare Workers](https://img.shields.io/badge/Deploy-to%20Cloudflare%20Workers-orange?logo=cloudflare&logoColor=white)](https://workers.cloudflare.com/)

A self-hosted, Bitwarden-compatible server that runs on Cloudflare Workers: D1 for data,
KV or R2 for attachments, Durable Objects for CPU-heavy work and live sync. Designed to be
deployed once and forgotten.

> **Migration notice:** the backend is being rewritten from Rust/WASM to TypeScript.
> The TypeScript implementation lives in `worker/` and is configured by
> `wrangler.toml`; the Rust reference implementation is still present and is what
> `wrangler.toml` currently deploys. See [Migration status](#migration-status).

## Features

* **Core vault:** create, read, update, delete ciphers and folders.
* **File attachments:** optional Cloudflare KV or R2 storage.
* **Bitwarden Send:** share encrypted text or files via a link, with optional passwords,
  expiry and access limits.
* **TOTP:** store secrets, generate codes, recovery codes.
* **Device management:** list devices, revoke sessions, push registration.
* **Live sync:** WebSocket notifications (desktop/extensions) and mobile push.
* **Bitwarden compatible:** works with the official clients.
* **Free to host:** runs within Cloudflare's free tier.

### Attachments

| Feature | KV | R2 |
|---|---|---|
| Max file size | **25 MB** (hard limit) | 100 MB (Workers request body limit) |
| Credit card required | **No** | Yes |
| Streaming I/O | Yes | Yes |

R2 takes priority when both are configured. Without either binding, attachment endpoints
return `400 Attachments are not enabled`.

### Send

* **Text Send** works without extra configuration. Because D1 caps a single row at 2 MB,
  text Sends are limited to ~1.8 MiB (`SEND_TEXT_MAX_BYTES`).
* **File Send** requires the same storage backend as attachments.

## Current status

Not feature-complete. Unsupported (and not planned):

* Organizations and sharing
* Two-factor authentication other than TOTP
* Emergency access
* Admin operations

The bundled web vault comes from Vaultwarden and exposes UI for features that this server
does not implement.

## Compatibility

* Browser extensions (tested with 2026.3.0 on Chrome)
* Android app (tested with 2026.4.0)
* iOS app (tested with 2026.4.0)

The server advertises `version: "2026.6.0"` in `/api/config`; clients use it for
backwards-compatibility decisions.

## Getting started

### Prerequisites

* Node.js 20+ and npm
* A Cloudflare account with D1 enabled
* Wrangler (`npx wrangler`, or install it globally)

### Required secrets

```bash
npx wrangler secret put JWT_SECRET            # access-token signing key
npx wrangler secret put JWT_REFRESH_SECRET    # refresh-token signing key
npx wrangler secret put ALLOWED_EMAILS        # comma-separated globs, e.g. "*@example.com"
```

`ALLOWED_EMAILS` is **mandatory for registration**: it is matched against the raw email
(case-sensitive) and any non-match returns `401 Not allowed to signup`. A missing secret
makes registration fail with `500`.

### Database

Set `D1_DATABASE_ID` in `wrangler.toml` (or via the deploy pipeline), then apply migrations:

```bash
npx wrangler d1 migrations apply vault1 --remote
```

On a brand-new database, `sql/schema.sql` can be applied first (it contains the full
schema); the deploy workflow does this automatically when the database has no tables.

## Configuration

Environment variables live under `[vars]` in `wrangler.toml` (or the Cloudflare dashboard).

| Variable | Default | Purpose |
|---|---|---|
| `BASE_URL` | derived from the request | Overrides the base URL used in file/Send URLs |
| `PASSWORD_ITERATIONS` | `600000` | Server-side PBKDF2 iterations (clamped up to 600k) |
| `LOGIN_MISSING_USER_DELAY_MS` | `550` | Base delay for unknown users (±30ms jitter) |
| `IMPORT_BATCH_SIZE` | `30` | Batch size for import / bulk rewrites (`0` = single batch) |
| `TRASH_AUTO_DELETE_DAYS` | `30` | Days before soft-deleted ciphers are purged (`0` disables) |
| `CIPHERS_DEFAULT_ROW_QUERY` | `false` | Fetch cipher JSON per row (avoids `SQLITE_TOOBIG`) |
| `SYNC_RESPONSE_PREALLOC_BYTES` | — | Initial capacity hint for `/api/sync` |
| `ATTACHMENT_MAX_BYTES` | unlimited | Max size per attachment |
| `ATTACHMENT_TOTAL_LIMIT_KB` | unlimited | Max attachment storage per user |
| `ATTACHMENT_TTL_SECS` | `300` | Upload/download URL lifetime |
| `SEND_TEXT_MAX_BYTES` | `1887436` | Max text Send size |
| `SEND_MAX_BYTES` | `104857600` | Max file Send size |
| `USER_SEND_LIMIT_KB` | unlimited | Max Send storage per user |
| `SEND_TTL_SECS` | `300` | Send upload/download URL lifetime |
| `DISABLE_USER_REGISTRATION` | `true` | Hides the registration button in the web UI |
| `AUTHENTICATOR_DISABLE_TIME_DRIFT` | `false` | Set `true` to reject TOTP codes outside the current step |
| `PUSH_ENABLED` | `false` | Enables mobile push (requires the secrets below) |
| `PUSH_RELAY_URI` | `https://push.bitwarden.com` | Push relay override |
| `PUSH_IDENTITY_URI` | `https://identity.bitwarden.com` | Push identity override |

### CPU offloading (Durable Objects)

Free-plan Workers have a small per-request CPU budget. Login, registration, password
changes, key rotation and import run PBKDF2 or parse large payloads, so they are forwarded
to the `HEAVY_DO` Durable Object (30s CPU budget) which reuses the exact same router.
Offloading is enabled whenever the `HEAVY_DO` binding exists.

### Live sync and push

* **WebSocket** (`NOTIFY_DO`): `/notifications/hub` and `/notifications/anonymous-hub`.
  Clients must send `{"protocol":"messagepack","version":1}`; frames are MessagePack
  prefixed with an unsigned LEB128 length.
* **Mobile push**: set `PUSH_ENABLED=true` plus `PUSH_INSTALLATION_ID` and
  `PUSH_INSTALLATION_KEY` (from <https://bitwarden.com/host/>).

### Rate limiting

Sensitive endpoints use Cloudflare's Rate Limiting binding. Missing bindings fail open.

| Endpoint | Limit | Key |
|---|---|---|
| `/identity/connect/token` (password) | 5/min | email + IP |
| `/identity/connect/token` (send access) | 15/min | IP |
| `/api/sends/access/*` | 10/min | IP |
| `/api/accounts/register` | 5/min | IP |
| `/api/accounts/prelogin` | 5/min | IP |

## Local development

```bash
npm install
npm run dev          # wrangler dev -c wrangler.toml --local --persist-to .wrangler/state
```

The API is served at `http://localhost:8787`. Secrets can be provided via `.dev.vars`
(`JWT_SECRET`, `JWT_REFRESH_SECRET`, `ALLOWED_EMAILS`).

### Tests

```bash
npm run typecheck
npm test             # unit + end-to-end handler tests against a real SQLite D1 adapter
npx biome check .
```

Handler tests run the real Hono app against `node:sqlite` with `sql/schema.sql`, so
SQL, crypto and response shapes are exercised without a Workers runtime. A separate
`@cloudflare/vitest-plugin` project (`vitest.integration.config.ts`) is provided for
workerd-specific behaviour (Durable Objects, WebSockets).

### Frontend

The web vault is served as static assets from `public/web-vault` (not committed). Download
a pinned `bw_web_builds` release and extract it there before deploying.

## Deployment

```bash
npx wrangler deploy
```

CI (`.github/workflows/push-cloudflare.yaml`) downloads the pinned web vault, applies D1
migrations, optionally seeds global equivalent domains, and deploys.

## Migration status

| Area | Status |
|---|---|
| TypeScript worker (`worker/`) | Implemented: identity, accounts, 2FA, devices, auth requests, ciphers, folders, sync, import, domains, attachments, Sends, notifications, push |
| Rust worker (`src/`) | Reference implementation; still deployed by `wrangler.toml` |
| Golden fixtures | Not yet captured (requires the Rust toolchain) |
| Cutover | Pending; `wrangler.toml` currently points at the TypeScript worker |

The Rust sources stay in the repository until contract fixtures are captured, because they
are the only executable specification of the wire format.

### Verification status

See [docs/verification.md](docs/verification.md) for the full matrix, reproduction commands
and the remaining verification checklist.

Verified locally (289 tests, `npm test`):

* HTTP handlers end to end against real SQLite (`node:sqlite` + `sql/schema.sql`).
* PBKDF2/TOTP/JWT vectors, MessagePack framing, error mapping, routing.

* PBKDF2 with 600k iterations on a deployed worker: **measured**. `node:crypto` and WebCrypto
  both reject >100k iterations on the edge, so `@noble/hashes` is the production path; it
  produces identical bytes and costs ~1.4–1.5 s per hash inside a Durable Object. See
  [tools/pbkdf2-probe/README.md](tools/pbkdf2-probe/README.md).

Not yet verified:

* Golden HTTP/WebSocket diff against the Rust worker (requires the Rust toolchain).
* Durable Objects end to end (`HeavyDo`, `NotifyDo`) — requires workerd.
* Mobile push against the real Bitwarden relay.

Known deviations from the Rust implementation:

* `reprompt` defaults to the float `0.0` in Rust; JSON serialization emits `0`.
* Malformed request bodies return plain-text rejections with matching status codes but not
  byte-identical messages.
* Response header ordering may differ.

## License

MIT — see [LICENSE](LICENSE).
