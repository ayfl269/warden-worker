# Deployment

Warden is a single Cloudflare Worker (Hono + TypeScript) backed by:

| Resource | Binding | Required | Purpose |
|---|---|---|---|
| D1 database | `vault1` | yes | users, ciphers, folders, sends, devices |
| KV namespace | `ATTACHMENTS_KV` | no | attachment blobs (or use R2 instead) |
| R2 bucket | `ATTACHMENTS_BUCKET` | no | attachment blobs, preferred when bound |
| Durable Object `HeavyDo` | `HEAVY_DO` | yes | PBKDF2-heavy endpoints (login, register, password verify) |
| Durable Object `NotifyDo` | `NOTIFY_DO` | yes | WebSocket notification hub |
| Static assets | — | no | the Web Vault frontend in `public/web-vault` |

Prerequisites: Node.js 20+, npm, and an authenticated wrangler
(`npx wrangler login`, or `CLOUDFLARE_API_TOKEN` in the environment).

## CLI deployment

### 1. Install dependencies

```bash
npm ci
```

### 2. Create the D1 database

```bash
npx wrangler d1 create vault1
```

Copy the returned `database_id` into `wrangler.toml`, replacing
`REPLACE_WITH_YOUR_D1_DATABASE_ID`:

```toml
[[d1_databases]]
binding = "vault1"
database_name = "vault1"
database_id = "<the uuid wrangler printed>"
```

The committed value is a placeholder, so `wrangler.toml` is safe to keep in git. If you
prefer not to edit the file, the same edit is what `scripts/cf-build.sh` performs from the
`D1_DATABASE_ID` build variable.

### 3. Create the attachments namespace (optional)

Attachments are optional. With neither KV nor R2 bound, every attachment endpoint returns
`501` and the rest of the server works normally.

```bash
npx wrangler kv namespace create ATTACHMENTS_KV
```

Add the returned id to the existing block:

```toml
[[kv_namespaces]]
binding = "ATTACHMENTS_KV"
id = "<the id wrangler printed>"
```

To use R2 instead (larger files, streaming), create a bucket and uncomment the
`[[r2_buckets]]` block — R2 wins over KV whenever both are bound:

```bash
npx wrangler r2 bucket create warden-attachments
```

### 4. Download the Web Vault frontend

```bash
npm run frontend
```

This downloads a pinned `bw_web_builds` release, extracts it into `public/web-vault`
(git-ignored), deletes the `*.map` files, and copies the UI override
`public/css/vaultwarden.css` into place. See [Frontend](#frontend) for version pinning.

The step is also wired as the `predev`/`predeploy` hook, so `npm run dev` and
`npm run deploy` populate the directory on demand. Run it explicitly only to pre-populate
the tree or to switch versions.

### 5. Create the schema

Fresh database:

```bash
npx wrangler d1 execute vault1 --remote --file sql/schema.sql
```

Existing database (incremental changes only):

```bash
npx wrangler d1 migrations apply vault1 --remote
```

`sql/schema.sql` already contains every bundled migration, so a fresh database must use
`--file sql/schema.sql`; running `migrations apply` on an empty database replays them all
one by one instead.

Optional: seed the global equivalent domains table (`/api/settings/domains` and
`/api/sync` return `globalEquivalentDomains: []` without it):

```bash
bash scripts/seed-global-domains.sh --db vault1 --remote
```

### 6. Set the runtime secrets

```bash
npx wrangler secret put JWT_SECRET
npx wrangler secret put JWT_REFRESH_SECRET
npx wrangler secret put ALLOWED_EMAILS          # e.g. "*@example.com", comma separated
```

`ALLOWED_EMAILS` is mandatory: registration returns `401 Not allowed to signup` unless the
raw email matches one of the globs, and a missing secret yields `500`.

`JWT_SECRET` and `JWT_REFRESH_SECRET` are only needed to *sign* tokens, so a deployment that
forgets them still registers accounts and then answers every login with `500
{"error":"Internal server error"}`. Check with `npx wrangler secret list` (names only) and
watch `npx wrangler tail` while retrying the login: the worker logs which secret is missing.

Optional mobile push relay settings: `PUSH_ENABLED`, `PUSH_RELAY_URI`,
`PUSH_IDENTITY_URI` as plain vars, and `PUSH_INSTALLATION_ID`,
`PUSH_INSTALLATION_KEY` as secrets. See
[Mobile Push Notifications](../README.md#mobile-push-notifications-optional).

### 7. Deploy

```bash
npm run deploy
```

This bundles `src/index.ts` and the PBKDF2 WebAssembly module, uploads the Worker, and
uploads `public/web-vault` as static assets.

### 8. Create the first account

`/api/config` reports `disableUserRegistration: true` unless
`DISABLE_USER_REGISTRATION` is literally `"false"`, and the Web Vault hides the "Create
account" button accordingly. On a fresh deployment there is no visible way to register, so
enable it for the first signup:

```bash
npx wrangler deploy --var DISABLE_USER_REGISTRATION:false
# register at https://<worker-url>/ (the link is at the bottom of the login page)
npx wrangler deploy --var DISABLE_USER_REGISTRATION:true
```

The email must match `ALLOWED_EMAILS`; widen that to `*` temporarily if needed. Register
through the browser rather than the API: the client derives the master key and hash from the
password you type, so an account created with arbitrary API values cannot be logged into.

### 9. Verify

```bash
curl -s https://<worker-url>/api/config | jq .version   # "2026.6.0"
curl -s https://<worker-url>/api/alive                  # timestamp; proves D1 works
curl -sI https://<worker-url>/ | head -n 1              # 200 from the asset layer
```

By default the `*.workers.dev` hostname is enabled (`workers_dev = true`) but can throw
`1101` errors; a custom domain is recommended — see
[Configure Custom Domain](../README.md#configure-custom-domain-optional).

## Frontend

The Web Vault is a prebuilt Angular bundle published by the Vaultwarden project as
`bw_web_builds` releases. It is not committed: it is ~40 MB compressed / ~80 MB extracted,
267 files of generated code that this repository never edits.

### How it is served

`wrangler.toml` declares it as static assets:

```toml
[assets]
directory = "./public/web-vault"
not_found_handling = "404-page"
html_handling = "auto-trailing-slash"
run_worker_first = ["/api/*", "/identity/*", "/notifications/*"]
```

`run_worker_first` is the important line: only API, Identity and notification paths reach
the Worker. Every other request (`/`, `/css/*`, `/app/*`, …) is answered by the asset layer
without spending Worker CPU, which is what keeps the frontend off the CPU budget.

`/` serves `index.html`; the Web Vault then uses hash routing (`/#/login`, `/#/vault`), so
no SPA fallback rewrite is needed and unknown paths correctly return `404.html`.

### Version pinning

```bash
npm run frontend                                  # pinned default (v2026.10.1)
BW_WEB_VERSION=v2026.11.0 npm run frontend        # specific tag
BW_WEB_VERSION=latest npm run frontend            # newest release
npm run frontend -- --force                       # re-download the current tag
```

The pinned default tracks the newest **stable** `bw_web_builds` release. Tags flagged
*prerelease* upstream (for example `v2026.11.0`, published as a preview of the next
Bitwarden release) work as well — they were verified against this server — but they are
opt-in on purpose. `latest` resolves whatever the newest release is, prerelease included.

The download is skipped once a complete tree has been extracted — tracked by
`public/.web-vault-version`, not by `index.html`, so an interrupted extraction is retried
instead of being mistaken for a good install. Always pass `--force` when changing
`BW_WEB_VERSION`: a stale tree would keep hashed chunks that the new `index.html` no longer
references.

The downloader resumes across dropped connections, verifies the archive against the
release's published `sha256sums.txt`, and starts over once if the checksum does not match —
a truncated `.tar.gz` still extracts partially, producing a site that is missing
lazy-loaded chunks, and a corrupted partial file is only detectable by hash.

Slow or filtered network? Node's `fetch` only honours a proxy when told to:

```bash
HTTP_PROXY=http://127.0.0.1:7890 HTTPS_PROXY=http://127.0.0.1:7890 \
  NODE_USE_ENV_PROXY=1 npm run frontend -- --force
```

The same variables make `scripts/cf-build.sh` faster on a constrained build runner.

### UI override

`public/css/vaultwarden.css` hides features this backend does not implement (organisation
billing, SSO, passkeys, Duo/YubiKey/WebAuthn 2FA, emergency access). `npm run frontend`
copies it to `public/web-vault/css/vaultwarden.css`; the Web Vault loads it from there.

### Local development

`npm run dev` runs the frontend hook first, then `wrangler dev --local`, so the full site
(assets + API) is available on the local port. Without `public/web-vault`, wrangler refuses
to start because the `[assets]` directory is missing.

## Continuous integration

`.github/workflows/ci.yml` runs on every push and pull request and only *checks* the code —
it does not deploy:

1. `npm run typecheck`
2. `npx biome check .`
3. `npm test` (unit and handler tests against a real SQLite-backed D1 adapter)
4. `npm run build:wasm` — rebuilds the PBKDF2 module
5. `npm run frontend` — downloads the Web Vault
6. `npx wrangler deploy --dry-run` — proves the Worker and assets bundle

## Deployment with GitHub Actions

`.github/workflows/deploy.yml` deploys on every push to `main`, and can also be started by
hand (**Actions → Deploy → Run workflow**, with an option to skip the D1 steps). It runs the
same two scripts as Cloudflare Workers Builds, so both pipelines behave identically:

```
npm ci → npm test → bash scripts/cf-build.sh → bash scripts/cf-deploy.sh
```

`cf-build.sh` rebuilds the WASM module, downloads the Web Vault, fills in the D1 id, typechecks
and dry-runs the bundle; `cf-deploy.sh` bootstraps/migrates D1 and runs `wrangler deploy`.

### Required secrets

| Secret | Required | Description |
|---|---|---|
| `CLOUDFLARE_API_TOKEN` | yes | Workers Scripts:Edit, D1:Edit, KV:Edit (+ R2:Edit when used) |
| `CLOUDFLARE_ACCOUNT_ID` | yes | account id |
| `D1_DATABASE_ID` | yes | production D1 database id |

### Optional variables

| Variable | Description |
|---|---|
| `BW_WEB_VERSION` | `bw_web_builds` tag (default `v2026.10.1`) |
| `KV_ID` | `ATTACHMENTS_KV` namespace id; enables the KV binding |
| `R2_NAME` | R2 bucket name; enables the `ATTACHMENTS_BUCKET` binding |
| `SEED_GLOBAL_DOMAINS` | `false` to skip seeding global equivalent domains |
| `GLOBAL_DOMAINS_URL` | pin a specific `global_domains.json` source |
| `SKIP_D1` | `1` to skip all D1 bootstrap/migrate/seed steps |
| `D1_NAME` | D1 **binding** name used by the migration steps (default `vault1`) |
| `WORKER_URL` | enables the post-deploy smoke step (e.g. `https://vault.example.com`) |

Runtime secrets (`JWT_SECRET`, `JWT_REFRESH_SECRET`, `ALLOWED_EMAILS`) are Worker secrets, not
build inputs: set them once with `wrangler secret put` and every deploy keeps them. The
workflow never touches them.

> `D1_NAME` must be the binding (`vault1`), not the database's own name: `wrangler d1
> migrations apply` only resolves bindings and `database_name` entries from `wrangler.toml`.

### Scheduled backups

`.github/workflows/backup-d1.yaml` exports the D1 database on a schedule and uploads it to
S3 or WebDAV. It needs these repository secrets:

| Secret | Required | Description |
|---|---|---|
| `CLOUDFLARE_API_TOKEN` | yes | token with **D1: Read** (and **Workers Scripts: Read** for `d1 list`) |
| `CLOUDFLARE_ACCOUNT_ID` | yes | account id |
| `D1_DATABASE_ID` | yes | production D1 database id |
| `S3_*` / `WEBDAV_*` / `BACKUP_ENCRYPTION_KEY` | no | backup destination and encryption |

See [backup.md](./backup.md) for the full backup setup.

## Cloudflare Workers Builds (dashboard)

[Workers Builds](https://developers.cloudflare.com/workers/ci-cd/builds/) is Cloudflare's
native Git integration: connect the repository once and every push builds and deploys on
Cloudflare, with no GitHub Actions deploy job. The pipeline is encapsulated in two scripts:

- [`scripts/cf-build.sh`](../scripts/cf-build.sh) (**Build** phase) — `npm ci`, rebuilds the
  PBKDF2 WebAssembly module, downloads the Web Vault frontend, substitutes the D1 database
  id, typechecks, and runs a bundle dry-run.
- [`scripts/cf-deploy.sh`](../scripts/cf-deploy.sh) (**Deploy** phase) — bootstraps/migrates
  D1, optionally seeds global domains, then runs `wrangler deploy`.

**No separate `CLOUDFLARE_API_TOKEN` is needed for the deploy itself.** Workers Builds
auto-generates a *build token* and uses it as the credential for the deploy phase, so the
D1 migrations in `cf-deploy.sh` reuse that one token.

### Setup

1. **Workers & Pages → `warden-worker-ts` → Settings → Build → Connect** your repository
   (production branch: `main`). This auto-generates the build token.

2. **Grant the build token D1 access** (one-time). The auto-generated token covers Workers
   Scripts / KV / R2 but **not** D1, so migrations would fail with an authorization error.
   Go to [My Profile → API Tokens](https://dash.cloudflare.com/profile/api-tokens), edit the
   token named **"Workers Builds"**, and add **Account → D1 → Edit**. (Or set `SKIP_D1=1`
   and apply migrations yourself.)

3. Set the build commands:

   | Field | Value |
   |---|---|
   | **Build command** | `bash scripts/cf-build.sh` |
   | **Deploy command** | `bash scripts/cf-deploy.sh` |

4. Add **build variables** (Settings → Build → *Variables and Secrets*). None are secrets.

   | Name | Required | Description |
   |---|---|---|
   | `D1_DATABASE_ID` | yes | production D1 database id (substituted into `wrangler.toml`) |
   | `BW_WEB_VERSION` | no | `bw_web_builds` tag (default `v2026.10.1`); `latest` tracks upstream |
   | `KV_ID` | no | `ATTACHMENTS_KV` namespace id; enables the KV binding |
   | `R2_NAME` | no | R2 bucket name; enables the `ATTACHMENTS_BUCKET` binding |
   | `SEED_GLOBAL_DOMAINS` | no | `false` to skip seeding global equivalent domains |
   | `GLOBAL_DOMAINS_URL` | no | pin a specific `global_domains.json` source |
   | `SKIP_D1` | no | `1` to skip all D1 bootstrap/migrate/seed steps (deploy still runs) |
   | `CLOUDFLARE_ACCOUNT_ID` | no | set only if wrangler cannot infer the account |

5. Set the runtime **Worker** secrets under the Worker's **Settings → Variables and
   Secrets** (not the build config): `ALLOWED_EMAILS`, `JWT_SECRET`, `JWT_REFRESH_SECRET`.

6. **Push to `main`** and watch the Worker's **Builds** tab.

> [!NOTE]
> The KV namespace id is not a build variable: create the namespace once
> (`npx wrangler kv namespace create ATTACHMENTS_KV`) and put its id in `wrangler.toml`
> before connecting the repository.

## Scheduled maintenance

`wrangler.toml` declares one cron trigger (`0 3 * * *`). The `scheduled()` handler runs five
purge tasks in order and logs a summary line per task:

| Task | Retention | Also deletes storage objects |
|---|---|---|
| unfinished attachment uploads | 1 day | — |
| ciphers in the trash | `TRASH_AUTO_DELETE_DAYS` (default 30) | yes |
| unfinished file Send uploads | 1 day | yes |
| Sends past `deletionDate` | — | yes |
| unanswered auth requests | 15 minutes | — |

`TRASH_AUTO_DELETE_DAYS=0` (or any negative value) disables trash auto-purge; the other four
tasks always run. The same cleanup happens synchronously on the delete paths — deleting a
cipher, emptying the vault, or deleting the account removes the attachment and Send objects
in KV/R2 immediately, so nothing is left behind between cron runs.

## Verification before cutover

1. Golden fixtures captured from the Rust worker (`npm run capture:golden`) and diffed
   against this implementation — see [verification.md](./verification.md).
2. PBKDF2 works on the real edge (600k iterations exceed the WebCrypto and `node:crypto`
   limits, which is why the Worker ships a hand-written WASM module):

   ```bash
   npx wrangler deploy -c tools/pbkdf2-probe/wrangler.toml
   curl -s "https://warden-pbkdf2-probe.<subdomain>.workers.dev/?skipNoble=1" | jq .verdict
   npx wrangler delete -c tools/pbkdf2-probe/wrangler.toml
   ```

   Expected `native-pbkdf2-ok`; the local runtime does not enforce the 100k-iteration cap,
   so this must run against a real deployment.
3. Real clients exercised: registration, login, 2FA, sync, attachment upload/download,
   Send (text + file), logout-all, WebSocket notifications.

## Troubleshooting

| Symptom | Cause |
|---|---|
| `The directory specified in your Wrangler configuration file does not exist` | `public/web-vault` is missing — run `npm run frontend` |
| `GET /` returns 404 while the API works | assets were not uploaded; check that `[assets]` is present and the directory was populated before deploy |
| login returns `error code: 1102` (CPU limit) | the `HEAVY_DO` binding is missing, so PBKDF2 runs on the main Worker |
| attachment endpoints return `501` | neither `ATTACHMENTS_KV` nor `ATTACHMENTS_BUCKET` is bound |
| `NotSupportedError: iteration counts above 100000 are not supported` | `compatibility_flags = ["nodejs_compat"]` was removed, or the WASM module failed to load and the `node:crypto` fallback was used |
| WebSocket notifications do not arrive | the `NOTIFY_DO` binding or its `do_v2` migration is missing |
