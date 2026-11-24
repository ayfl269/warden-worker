# Verification status

What is proven about this implementation, how to reproduce it, and what still requires an
environment that CI or a developer machine must provide.

## Run everything locally

```bash
npm ci
npm run typecheck
npm test
npx biome check .
npm run build:wasm
npm run frontend
npx wrangler deploy --dry-run --outdir .wrangler/dry-run
```

Expected: `tsc` exits 0, 285 tests pass, no lint errors, and the bundle builds (~1.1 MB,
~200 KiB gzip, plus the 6.7 KB PBKDF2 WASM module).

## What is verified

| Area | Test | Notes |
|---|---|---|
| PBKDF2 | `tests/unit/password.test.ts` | Published PBKDF2-HMAC-SHA256 vectors (c=1/2/4096), cross-checked against `@noble/hashes`, 600k derivation, and the AssemblyScript module against the same vectors. |
| TOTP | `tests/unit/totp.test.ts` | RFC 6238 vectors (6 timestamps), replay protection, drift window, base32 RFC 4648 vector. |
| JWT | `tests/unit/jwt.test.ts` | Claim names, 60s leeway, tamper/expiry rejection, attachment `exp = now + TTL - 60`. |
| MessagePack | `tests/unit/notifications-msgpack.test.ts` | LEB128 framing, ext `-1` timestamp round-trip, `ReceiveMessage` envelope layout, upstream `AuthRequestResponseRecieved` spelling. |
| Fan-out | `tests/unit/notifications-publish.test.ts` | Captures the fan-out request, decodes the frame, asserts entity payloads and selectors. |
| Push relay | `tests/unit/notifications-push.test.ts` | Gate, OAuth2 form fields, cache key/max-age, envelope key order, no network when disabled. |
| HTTP behaviour | `tests/unit/handlers-*.test.ts` | Real Hono app + real SQLite (`node:sqlite` + `sql/schema.sql`): identity, accounts, 2FA, devices, auth requests, ciphers, folders, sync, import, domains, attachments (streaming + multipart), Sends (text/file/access), misc stubs. |
| Wire contract | `tests/golden/http.json` | 38 recorded HTTP exchanges from the Rust worker this implementation was ported from. All 38 reproduce byte-identically. |

### Byte-level HTTP contract

`tests/golden/http.json` holds 38 request/response pairs captured from the reference
implementation. Volatile values (ids, timestamps, JWTs, tokens) are normalized at capture
time, so the fixture is deterministic.

```bash
# Replay the fixtures against a running instance and diff.
BASE_URL=http://127.0.0.1:8787 node tools/diff-golden.mjs

# Re-capture (needs a seeded account and GOLDEN_PASSWORD_HASH).
BASE_URL=http://127.0.0.1:8787 GOLDEN_EMAIL=golden@example.com \
  GOLDEN_PASSWORD_HASH_FILE=.golden-hash npm run capture:golden
```

`tools/diff-golden.mjs` compares status, headers and JSON with **sorted keys**: the Rust
worker emitted two different field orders depending on the code path (`json!` macro vs
SQLite `json_object`), so key order is not part of the contract.

Result: **38/38 identical**. This is what pins error strings, status-code quirks and the
mixed-case token response (`access_token` plus PascalCase `Key`/`Kdf`/`UserDecryptionOptions`
and camelCase `AccountKeys`).

## What is NOT verified (and how to verify it)

### 1. PBKDF2 with 600k iterations on the real edge

Measured on a deployed worker (2026-11-24, colo NRT) — see `tools/pbkdf2-probe/README.md`:

* `node:crypto.pbkdf2Sync` **fails** at 600k: `iteration counts above 100000 are not supported`.
  In workerd it is implemented over the same WebCrypto PBKDF2, so the cap applies.
* A pure-JS implementation in the **main worker** fails with `error code: 1102` (CPU limit).
* The hand-written AssemblyScript module inside a **Durable Object** succeeds at
  **~0.55 s per hash** (Node, same machine), with output byte-identical to Node
  (`669cfe52…5178`).

Consequences: `wasm/pbkdf2.wasm` is the production path; `@noble/hashes` is only a fallback
for environments where the WASM module cannot be instantiated. Login latency measured
end-to-end is ~1.3–1.9 s including the round trip.

Reproduce:

```bash
npx wrangler deploy -c tools/pbkdf2-probe/wrangler.toml
curl -s "https://warden-pbkdf2-probe.<subdomain>.workers.dev/?do=1"
npx wrangler delete -c tools/pbkdf2-probe/wrangler.toml
```

#### Implementation comparison

Same machine (Node 26), same input, 600k iterations:

| Implementation | Time | Verdict |
|---|---|---|
| `node:crypto.pbkdf2Sync` | 292 ms | Fastest, but capped at 100k on the edge |
| AssemblyScript, naive (4 compressions/iter) | 1,479 ms | Rejected |
| AssemblyScript, HMAC state reuse (2/iter) | 760 ms | — |
| AssemblyScript, state reuse + `-O3` | 652 ms | — |
| AssemblyScript, `-O3` + inlined block path + `@inline` | **555 ms** | **Adopted** (`wasm/pbkdf2.ts`) |
| `@noble/hashes` (pure JS) | 986 ms | Fallback |
| `hash-wasm` 4.13.0 (WASM) | 1,855–1,896 ms | Rejected: ~2× slower than noble, 272 KB |

All produce identical bytes (`669cfe52…5178`), so the decision was purely about speed.

Deployed measurement (login end-to-end through the Durable Object):

| Backend | Cold | Warm |
|---|---|---|
| `@noble/hashes` | 3.07 s | ~2.3 s |
| `wasm/pbkdf2.wasm` | 1.91 s | **1.36–1.55 s** |

Login returning `200` also proves the WASM output matches hashes stored earlier by the
native/noble path.

### 2. Durable Objects and WebSockets

Requires a full Workers runtime (the workerd pool cannot be spawned in every sandbox).

```bash
npm run test:integration   # tests/integration via @cloudflare/vitest-plugin
```

Covers `HeavyDo` forwarding and `NotifyDo` handshake/fan-out. Not covered yet: hibernation
eviction behaviour, and WebSocket frames through a proxy-capable client.

### 3. Frontend asset routing

`[assets]` in `wrangler.toml` is the same configuration the Rust worker served in production
(`directory`, `not_found_handling = "404-page"`, `html_handling = "auto-trailing-slash"`,
`run_worker_first = ["/api/*", "/identity/*", "/notifications/*"]`). `wrangler deploy
--dry-run` confirms the asset directory is read and bundled, but the routing itself is
platform behaviour that only a real deployment can exercise:

```bash
curl -sI https://<worker-url>/ | head -n 1            # 200, index.html
curl -sI https://<worker-url>/css/vaultwarden.css | head -n 1   # 200, from the asset layer
curl -s https://<worker-url>/api/config | jq .version # 2026.6.0, from the Worker
curl -sI https://<worker-url>/definitely-missing | head -n 1    # 404, 404.html
```

### 4. Real clients

Manual matrix, run against a deployed instance:

- Chrome extension (2026.3.0): register, login, TOTP, create/edit/delete, sync.
- Android (2026.4.0) / iOS (2026.4.0): login, push registration, live sync.
- Web vault: upload/download attachment, create text + file Send, logout all.

## Known deviations from the reference implementation

1. `reprompt` defaults to the float `0.0` in Rust; JSON serialization emits `0`.
2. Malformed request bodies return plain-text rejections with matching status codes
   (400/415/422) but not byte-identical messages.
3. Response header ordering may differ.

## Removed at repository split

`tests/unit/route-parity.test.ts` and `tests/unit/heavy-routes.test.ts` compared the
TypeScript route table against `rust/router.rs` and `rust/entry.js`. Those files live in the
original Rust repository, so both tests were dropped when this repository was split. The
golden fixtures in `tests/golden/` still pin the observable behaviour, and
`tests/unit/handlers-*.test.ts` covers every route the table declares.
