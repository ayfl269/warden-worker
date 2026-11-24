# Verification status

What is proven about the TypeScript implementation, how to reproduce it, and what still
requires an environment this repository's CI or a developer machine must provide.

## Run everything locally

```bash
npm ci
npm run typecheck
npm test
npx biome check --diagnostic-level=error .
npx wrangler deploy --dry-run --outdir .wrangler/dry-run -c wrangler.toml
```

Expected: `tsc` exits 0, 289 tests pass, no lint errors, bundle builds (~99 KiB, ~25 KiB gzip).

## What is verified

| Area | Test | Notes |
|---|---|---|
| Route table | `tests/unit/route-parity.test.ts` | Parses `src/router.rs` and compares every `METHOD /path` with `app.routes`; param names normalized. Currently **exactly equal**. |
| CPU-offload table | `tests/unit/heavy-routes.test.ts` | Parses `HEAVY_DO_ROUTE_METHODS` out of `src/entry.js` and compares path + method sets. Currently **exactly equal**. |
| PBKDF2 | `tests/unit/password.test.ts` | Published PBKDF2-HMAC-SHA256 vectors (c=1/2/4096), cross-checked against `@noble/hashes`, 600k derivation. |
| TOTP | `tests/unit/totp.test.ts` | RFC 6238 vectors (6 timestamps), replay protection, drift window, base32 RFC 4648 vector. |
| JWT | `tests/unit/jwt.test.ts` | Claim names, 60s leeway, tamper/expiry rejection, attachment `exp = now + TTL - 60`. |
| MessagePack | `tests/unit/notifications-msgpack.test.ts` | LEB128 framing, ext `-1` timestamp round-trip, `ReceiveMessage` envelope layout, upstream `AuthRequestResponseRecieved` spelling. |
| Fan-out | `tests/unit/notifications-publish.test.ts` | Captures the fan-out request, decodes the frame, asserts entity payloads and selectors. |
| Push relay | `tests/unit/notifications-push.test.ts` | Gate, OAuth2 form fields, cache key/max-age, envelope key order, no network when disabled. |
| HTTP behaviour | `tests/unit/handlers-*.test.ts` | Real Hono app + real SQLite (`node:sqlite` + `sql/schema.sql`): identity, accounts, 2FA, devices, auth requests, ciphers, folders, sync, import, domains, attachments (streaming + multipart), Sends (text/file/access), misc stubs. |

## What is NOT verified (and how to verify it)

### 1. Byte-level HTTP contract vs the Rust worker

Requires a Rust toolchain (the reference implementation is the executable spec).

```bash
# terminal 1
wrangler dev --local --persist-to .wrangler/state

# terminal 2 (needs .dev.vars with JWT_SECRET, JWT_REFRESH_SECRET, ALLOWED_EMAILS)
BASE_URL=http://127.0.0.1:8787 npm run capture:golden
# → tests/golden/http.json
```

Then replay each recorded request against the TypeScript worker (same seeded database) and
compare status + normalized JSON. Volatile values (ids, timestamps, JWTs, tokens) are
already normalized by the capture script.

### 2. PBKDF2 with 600k iterations on the real edge

**Measured on a deployed worker (2026-11-24, colo NRT) — see `tools/pbkdf2-probe/README.md`:**

* `node:crypto.pbkdf2Sync` **fails** at 600k: `iteration counts above 100000 are not supported`.
  In workerd it is implemented over the same WebCrypto PBKDF2, so the cap applies.
* `@noble/hashes` in the **main worker** fails with `error code: 1102` (CPU limit).
* `@noble/hashes` inside a **Durable Object** succeeds at **~1.4–1.5 s per hash**, with
  output byte-identical to Node.

Consequences: the fallback in `worker/auth/password.ts` is the production path, and every
password flow costs ~1.5 s of DO CPU. Login latency is therefore ~1.5–2 s, which misses the
original < 1.5 s target. If that matters, switch to a WASM PBKDF2 (`hash-wasm`) — that adds a
WASM artifact and needs sign-off.

Reproduce:

```bash
npx wrangler deploy -c tools/pbkdf2-probe/wrangler.toml
curl -s "https://warden-pbkdf2-probe.<subdomain>.workers.dev/?do=1"
npx wrangler delete -c tools/pbkdf2-probe/wrangler.toml
```

#### Alternatives evaluated

Same machine (Node 26), same input, 600k iterations:

| Implementation | Time | Verdict |
|---|---|---|
| `node:crypto.pbkdf2Sync` | 292 ms | Fast, but capped at 100k on the edge |
| `@noble/hashes` (pure JS) | 986 ms | **Current fallback** |
| `hash-wasm` 4.13.0 (WASM) | 1,855–1,896 ms | **Rejected**: ~2× slower than noble, and `dist/index.esm.js` is 272 KB |

All three produce identical bytes (`669cfe52…5178`), so the decision is purely about speed.
Replacing noble with `hash-wasm` was therefore measured and abandoned.

#### Update: hand-written AssemblyScript WASM adopted

A custom SHA-256 + HMAC + PBKDF2 module (`wasm/pbkdf2.ts`, 3 KB) is now the preferred
backend. The decisive optimisation is **HMAC state reuse**: the key never changes inside
PBKDF2, so `SHA256(K^ipad)` and `SHA256(K^opad)` are precomputed once and each iteration
needs only 2 compressions instead of 4.

| Variant | 600k (Node) |
|---|---|
| AssemblyScript, naive (4 compressions/iter) | 1479 ms |
| AssemblyScript, state reuse (2/iter) | 760 ms |
| AssemblyScript, state reuse + `-O3` | **652 ms** |
| `@noble/hashes` | 986 ms |

Deployed measurement (login end-to-end through the Durable Object, staging worker):

| Backend | Cold | Warm |
|---|---|---|
| noble | 3.07 s | ~2.3 s |
| wasm (O3) | 1.91 s | **1.36–1.55 s** |

Login returning `200` also proves the wasm output is byte-identical to the hashes stored
earlier by the native/noble path.

### 3. Durable Objects and WebSockets

Requires a full Workers runtime (the pool worker cannot be spawned in every sandbox).

```bash
npm run test:integration   # tests/integration via @cloudflare/vitest-plugin
```

Covers `HeavyDo` forwarding and `NotifyDo` handshake/fan-out. Not covered yet: hibernation
eviction behaviour.

### 4. Real clients

Manual matrix, run against a deployed instance:

- Chrome extension (2026.3.0): register, login, TOTP, create/edit/delete, sync.
- Android (2026.4.0) / iOS (2026.4.0): login, push registration, live sync.
- Web vault: upload/download attachment, create text + file Send, logout all.

## Known deviations from the Rust implementation

1. `reprompt` defaults to the float `0.0` in Rust; JSON serialization emits `0`.
2. Malformed request bodies return plain-text rejections with matching status codes
   (400/415/422) but not byte-identical messages.
3. Response header ordering may differ.

## Tests coupled to the Rust sources

`route-parity.test.ts` reads `src/router.rs` and `heavy-routes.test.ts` reads `src/entry.js`.
When the Rust sources are deleted at cutover, replace both with frozen snapshots of the
expected route/method lists, or drop them once golden fixtures cover the same ground.
