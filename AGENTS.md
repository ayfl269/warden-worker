# Repository Guidelines

## Overview

Warden is a minimal, Bitwarden-compatible backend for Cloudflare Workers, written in
TypeScript (Hono + D1 + Durable Objects). It was ported 1:1 from a Rust/WASM worker; the wire
format is locked by the golden fixtures in `tests/golden/`, which are the executable
specification of the client contract.

- `src/` — the Worker (Hono app, handlers, auth, D1 access, Durable Objects).
- `wasm/` — hand-written AssemblyScript: the PBKDF2 SHA-256 core used in production.
- `wrangler.toml` — Worker config; also declares `[assets]` for the frontend.
- `public/web-vault/` — prebuilt Bitwarden Web Vault, downloaded by
  `tools/fetch-web-vault.mjs`; never edit or commit it.
- `tests/golden/` — recorded HTTP responses from the reference implementation.

## Structure

- `src/index.ts` — entry point: trailing-slash normalization, NotifyDo/HeavyDo routing,
  streaming interception, Hono app.
- `src/app.ts` — CORS, 404/405, error mapping.
- `src/router.ts` — the full route table.
- `src/handlers/` — endpoint implementations, one file per feature.
- `src/models/` — request/response payloads and serializers.
- `src/auth/` — PBKDF2, JWT, TOTP, device types, auth middleware.
- `src/db/` — D1 access; SQL strings intentionally match the reference implementation.
- `src/notifications/` — MessagePack framing, fan-out, push relay.
- `src/durable/` — `HeavyDo` (reuses the Hono app) and `NotifyDo` (WebSocket hub).
- `tests/unit/` — handler tests against a real SQLite-backed D1 adapter.
- `tests/integration/` — workerd tests via `@cloudflare/vitest-plugin`.
- `tools/` — frontend download, golden capture/diff, local HTTP harness.
- `migrations/`, `sql/` — D1 schema.
- `docs/` — deployment and backup playbooks.

## Commands

```bash
npm install
npm run frontend       # download public/web-vault (also runs before dev/deploy)
npm run dev            # local worker + static assets
npm run typecheck      # tsc --noEmit
npm test               # unit + handler tests
npm run test:integration  # workerd tests (requires a full runtime)
npm run build:wasm     # rebuild wasm/pbkdf2.wasm from wasm/pbkdf2.ts
npx biome check .      # lint + format check
npm run deploy         # fetch frontend + wrangler deploy
```

## Style

- TypeScript strict mode; no `any` in new code.
- Keep routing in `src/router.ts`, endpoint logic in `src/handlers/*`.
- Keep edge-only concerns (streaming, sharding) in `src/index.ts` / `src/durable/*`.
- Formatting: Biome, 2-space indent, single quotes, 100 columns.
- SQL: copy the reference queries verbatim unless fixing a bug; response field names and
  error strings are part of the client contract.

## Testing

- Prefer handler tests in `tests/unit/` — they exercise the real Hono app, real SQL
  (`node:sqlite` + `sql/schema.sql`) and real crypto.
- Use `tests/integration/` only for workerd-specific behaviour (DOs, WebSockets).
- Every new endpoint needs at least one success path and one error path.
- Contract changes must keep the golden fixtures green: a response that differs from
  `tests/golden/http.json` is a regression unless the fixture is regenerated on purpose.

## Commits and PRs

Conventional Commits (`feat:`, `fix:`, `docs:`, `refactor:`, `chore:`). PRs should describe
behaviour changes and list operational impacts: D1 migrations, new env vars/secrets,
R2/DO bindings, frontend version bumps.

## Security

- Never commit secrets. Use `.dev.vars` locally and GitHub Secrets in CI.
- Required secrets: `JWT_SECRET`, `JWT_REFRESH_SECRET`, `ALLOWED_EMAILS` (registration
  allow-list, matched against the raw email), `D1_DATABASE_ID`.
- Optional push secrets: `PUSH_INSTALLATION_ID`, `PUSH_INSTALLATION_KEY`.
- `wrangler.toml` ships placeholder resource ids on purpose; keep it that way.
