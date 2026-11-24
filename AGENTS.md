# Repository Guidelines

## Overview

Warden is a minimal, Bitwarden-compatible backend for Cloudflare Workers.

The backend is being rewritten from Rust/WASM to TypeScript:

- `worker/` — the TypeScript implementation (Hono + D1 + Durable Objects).
- `src/` — the Rust reference implementation. It is the executable specification of the
  wire format and is still what `wrangler.toml` deploys.
- `wrangler.toml` — configuration for the TypeScript worker (separate file on purpose:
  CI rewrites `${D1_DATABASE_ID}` with `sed`, which would corrupt an `_TS` placeholder in
  the same file).
- `vaultwarden/` — reference only, not reused.
- `public/web-vault/` — prebuilt frontend, downloaded during deploy; do not edit.

## Structure

- `worker/index.ts` — entry point: trailing-slash normalization, NotifyDo/HeavyDo routing,
  streaming interception, Hono app.
- `worker/app.ts` — CORS, 404/405, error mapping.
- `worker/router.ts` — the full route table; mirrors `src/router.rs`.
- `worker/handlers/` — endpoint implementations, one file per feature.
- `worker/models/` — request/response payloads and serializers.
- `worker/auth/` — PBKDF2, JWT, TOTP, device types, auth middleware.
- `worker/db/` — D1 access; SQL strings intentionally match the Rust implementation.
- `worker/notifications/` — MessagePack framing, fan-out, push relay.
- `worker/durable/` — `HeavyDo` (reuses the Hono app) and `NotifyDo` (WebSocket hub).
- `tests/unit/` — handler tests against a real SQLite-backed D1 adapter.
- `tests/integration/` — workerd tests via `@cloudflare/vitest-plugin`.
- `migrations/`, `sql/` — D1 schema.
- `docs/` — deployment and backup playbooks.

## Commands

```bash
npm install
npm run dev            # local worker (wrangler.toml)
npm run typecheck      # tsc --noEmit
npm test               # unit + handler tests
npm run test:integration  # workerd tests (requires a full runtime)
npx biome check .      # lint + format check
npx wrangler deploy -c wrangler.toml
```

## Style

- TypeScript strict mode; no `any` in new code.
- Keep routing in `worker/router.ts`, endpoint logic in `worker/handlers/*`.
- Keep edge-only concerns (streaming, sharding) in `worker/index.ts` / `worker/durable/*`.
- Formatting: Biome, 2-space indent, single quotes, 100 columns.
- SQL: copy the Rust queries verbatim unless fixing a bug; response field names and error
  strings are part of the client contract.

## Testing

- Prefer handler tests in `tests/unit/` — they exercise the real Hono app, real SQL
  (`node:sqlite` + `sql/schema.sql`) and real crypto.
- Use `tests/integration/` only for workerd-specific behaviour (DOs, WebSockets).
- Every new endpoint needs at least one success path and one error path.

## Commits and PRs

Conventional Commits (`feat:`, `fix:`, `docs:`, `refactor:`, `chore:`). PRs should describe
behaviour changes and list operational impacts: D1 migrations, new env vars/secrets,
R2/DO bindings.

## Security

- Never commit secrets. Use `.dev.vars` locally and GitHub Secrets in CI.
- Required secrets: `JWT_SECRET`, `JWT_REFRESH_SECRET`, `ALLOWED_EMAILS` (registration
  allow-list, matched against the raw email), `D1_DATABASE_ID`.
- Optional push secrets: `PUSH_INSTALLATION_ID`, `PUSH_INSTALLATION_KEY`.
