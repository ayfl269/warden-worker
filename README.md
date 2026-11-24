# Warden: A Bitwarden-compatible server for Cloudflare Workers

[![Powered by Cloudflare](https://img.shields.io/badge/Powered%20by-Cloudflare-F38020?logo=cloudflare&logoColor=white)](https://www.cloudflare.com/)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Deploy to Cloudflare Workers](https://img.shields.io/badge/Deploy-to%20Cloudflare%20Workers-orange?logo=cloudflare&logoColor=white)](https://workers.cloudflare.com/)

A self-hosted, Bitwarden-compatible server that runs on Cloudflare Workers: D1 for data,
KV or R2 for attachments, Durable Objects for CPU-heavy work and live sync. Designed to be
deployed once and forgotten.

The backend is written in TypeScript (Hono + D1 + Durable Objects). It was ported 1:1 from
the original Rust/WASM worker; the wire format is locked by golden fixtures captured from
that implementation — see [docs/verification.md](docs/verification.md).

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

### Create the first account

The Web Vault hides its "Create account" button by default, because
`DISABLE_USER_REGISTRATION` is treated as `true` unless it is literally `false`. On a fresh
deployment that leaves no visible way in, so turn the button on, register, then turn it off:

```bash
# 1. show the button (plain variable, not a secret)
npx wrangler deploy --var DISABLE_USER_REGISTRATION:false
#    or set DISABLE_USER_REGISTRATION = "false" under [vars] in wrangler.toml and deploy

# 2. open https://vault.example.com/, click "Create account", register

# 3. close it again once the account exists
npx wrangler deploy --var DISABLE_USER_REGISTRATION:true
```

The email must match `ALLOWED_EMAILS` (set it to `*` while bootstrapping, then narrow it to
your own address). Registering through the UI matters: the browser derives the master key and
hash from your password, so an account created by a raw API call with arbitrary values cannot
be logged into.

After the account exists you can log in from the web vault, the browser extension and the
mobile apps — registration is only needed once.

### Database

Replace `REPLACE_WITH_YOUR_D1_DATABASE_ID` in `wrangler.toml` with the id from
`npx wrangler d1 create vault1`, then create the schema:

```bash
npx wrangler d1 execute vault1 --remote --file sql/schema.sql   # fresh database
npx wrangler d1 migrations apply vault1 --remote                # existing database
```

### Frontend

The Bitwarden Web Vault is served as static assets from `public/web-vault`, which is not
committed. Populate it with:

```bash
npm run frontend          # pinned bw_web_builds release; BW_WEB_VERSION=latest to track upstream
```

`npm run dev` and `npm run deploy` run this automatically, so the directory is only fetched
once. See [docs/deployment.md](docs/deployment.md#frontend) for version pinning and how the
asset routing works.

## Configuration

Environment variables live under `[vars]` in `wrangler.toml` (or the Cloudflare dashboard).

| Variable | Default | Purpose |
|---|---|---|
| `BASE_URL` | derived from the request | Overrides the base URL used in file/Send URLs |
| `PASSWORD_ITERATIONS` | `600000` | Server-side PBKDF2 iterations (clamped up to 600k) |
| `LOGIN_MISSING_USER_DELAY_MS` | `1200` | Base delay for unknown users (±30ms jitter); tune to the real PBKDF2 cost so timing does not reveal account existence |
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
| `EXPOSE_PASSWORD_HINTS` | `false` | Set `1` to return the password hint in the API response (default: hint is not disclosed) |
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

### Scheduled maintenance

The cron trigger (`0 3 * * *`) runs five purge tasks, in this order:

1. unfinished attachment uploads older than a day (`attachments_pending`)
2. ciphers trashed longer than `TRASH_AUTO_DELETE_DAYS` (default 30, `0` or negative
   disables), **including their attachment objects**, then a revision bump so clients resync
3. unfinished file Send uploads older than a day (`sends_pending`)
4. Sends past their `deletionDate`, **including their file objects**
5. auth requests older than 15 minutes

Each task is isolated: a failure is logged and the rest still run.

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
npm run dev          # fetches the frontend if needed, then wrangler dev --local
```

The site is served at `http://localhost:8787` — the API *and* the Web Vault. Secrets can be
provided via `.dev.vars` (`JWT_SECRET`, `JWT_REFRESH_SECRET`, `ALLOWED_EMAILS`).

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

### PBKDF2 WebAssembly module

`wasm/pbkdf2.ts` is hand-written AssemblyScript, compiled to `wasm/pbkdf2.wasm` (committed):

```bash
npm run build:wasm
```

It is the production PBKDF2 backend: 600k iterations exceed both the WebCrypto and the
`node:crypto` caps on the edge, and a pure-JS implementation blows the per-request CPU
budget. The module reuses the HMAC key schedule (2 SHA-256 compressions per iteration
instead of 4).

## Deployment

```bash
npm run deploy
```

This fetches the frontend if needed and runs `wrangler deploy`, which uploads the Worker and
the static assets. See [docs/deployment.md](docs/deployment.md) for the full guide, including
the Cloudflare Workers Builds pipeline (`scripts/cf-build.sh` + `scripts/cf-deploy.sh`) and
the D1/KV/R2 setup.

Two workflows ship with the repository:

* `.github/workflows/ci.yml` — typechecks, lints, runs the test suite, rebuilds the WASM
  module, downloads the frontend and verifies the bundle with `wrangler deploy --dry-run`.
  It does not deploy.
* `.github/workflows/deploy.yml` — deploys on every push to `main` (or on demand) by running
  the same two scripts as Workers Builds: `npm ci`, tests, build, D1 migrations, deploy, and
  an optional post-deploy probe when the `WORKER_URL` variable is set.

`backup-d1.yaml` handles scheduled D1 exports.

## Verification status

See [docs/verification.md](docs/verification.md) for the full matrix, reproduction commands
and the remaining checklist.

Verified (`npm test`, 301 tests):

* HTTP handlers end to end against real SQLite (`node:sqlite` + `sql/schema.sql`).
* PBKDF2/TOTP/JWT vectors, MessagePack framing, error mapping, routing.
* **38/38 golden HTTP fixtures byte-identical** to the Rust worker they were captured from
  (`tests/golden/http.json`, replayable with `tools/diff-golden.mjs`).

Verified against a live deployment:

* PBKDF2 with 600k iterations: the `wasm/pbkdf2.wasm` module produces the expected digest on
  the edge in ~0.55 s per hash, inside a Durable Object. WebCrypto and `node:crypto` both
  reject >100k iterations there, which is why the module exists.

Not yet verified:

* Durable Objects end to end (`HeavyDo`, `NotifyDo`) — requires workerd, unavailable in the
  development sandbox; covered indirectly by the handler tests.
* WebSocket notification frames through a proxy-capable client.
* Mobile push against the real Bitwarden relay.

Known deviations from the Rust implementation:

* `reprompt` defaults to the float `0.0` in Rust; JSON serialization emits `0`.
* Malformed request bodies return plain-text rejections with matching status codes but not
  byte-identical messages.
* Response header ordering and JSON field order may differ (the Rust worker itself emits two
  different field orders depending on the code path).

## License

MIT — see [LICENSE](LICENSE).
