# PBKDF2 production probe

Answers the question that decides the password-hashing strategy:

> Can the worker derive a 600k-iteration PBKDF2 key on the Cloudflare edge, and how fast?

## Result (measured 2026-11-24, colo NRT)

| Path | 600k iterations | Outcome |
|---|---|---|
| `node:crypto.pbkdf2Sync` | — | **Fails**: `NotSupportedError: Pbkdf2 failed: iteration counts above 100000 are not supported (requested 600000)` |
| WebCrypto `deriveBits` | — | Fails with the same 100k cap |
| `@noble/hashes` in the **main worker** | — | **Fails**: `error code: 1102` (exceeded CPU limit) |
| `@noble/hashes` inside a **Durable Object** | ~1.4–1.5 s | Works; output is byte-identical to Node |

`node:crypto` is *not* an escape hatch: in workerd it is implemented over the same
WebCrypto PBKDF2, so the 100k cap applies.

### How the timing was obtained

Worker clocks (`Date.now`, `performance.now`) are frozen during a request, so the probe
measures wall time from the client with `?do=1&n=<repetitions>`:

| n | wall time |
|---|---|
| 1 | 1.845 s |
| 5 | 7.585 s |
| 10 | 15.236 s |

Delta ≈ 1.45 s per 600k derivation (the n=1 run includes ~0.4 s of proxy + DO startup).

Correctness: the derived key for `password`/`salt`/600k was
`669cfe52482116fda1aa2cbe409b2f56c8e4563752b7a28f6eaab614ee005178`, identical to Node's
`pbkdf2Sync` output.

## Consequences

- `worker/auth/password.ts` tries `node:crypto` first and permanently falls back to
  `@noble/hashes` after the first `NotSupportedError`. In production every 600k hash
  therefore costs ~1.5 s of CPU.
- All password flows (login, registration, password change, KDF change, key rotation) are
  already offloaded to `HEAVY_DO`, which has a 30 s CPU budget, so they complete — but
  login latency is ~1.5–2 s.
- If that latency is unacceptable, the next step is a WASM PBKDF2 (`hash-wasm`, ~5–10×
  faster). That introduces a WASM artifact and needs explicit sign-off.

## Run it yourself

```bash
npx wrangler deploy -c tools/pbkdf2-probe/wrangler.toml
curl -s "https://warden-pbkdf2-probe.<subdomain>.workers.dev/"          # fast checks
curl -s "https://warden-pbkdf2-probe.<subdomain>.workers.dev/?do=1"     # DO timing
npx wrangler delete -c tools/pbkdf2-probe/wrangler.toml
```

`*.workers.dev` may be DNS-poisoned on some networks; use a proxy
(`curl -x http://127.0.0.1:<port>`) if so.
