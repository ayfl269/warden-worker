#!/usr/bin/env bash
#
# scripts/cf-build.sh  --  BUILD phase for Cloudflare Workers Builds.
#
# Paired with scripts/cf-deploy.sh (the Deploy phase). Together they let a plain
# `git push` build and deploy the Worker from Cloudflare's dashboard Git
# integration, with no GitHub Actions required.
#
# Configure both in the dashboard under:
#   Workers & Pages > warden-worker-ts > Settings > Build
#
#   Build command:   bash scripts/cf-build.sh
#   Deploy command:  bash scripts/cf-deploy.sh
#
# This phase installs Node dependencies, compiles the PBKDF2 WebAssembly module,
# downloads the Web Vault frontend (static assets), configures wrangler.toml and
# verifies that the Worker bundles. D1 migrations run in the Deploy phase
# (cf-deploy.sh), where the auto-generated build token is the active credential
# -- so no extra API token is needed here; just grant that build token D1:Edit
# once (see cf-deploy.sh / docs/deployment.md).
#
# Build variables (Settings > Build > "Variables and Secrets"):
#   D1_DATABASE_ID        (required)  production D1 database id (substituted into wrangler.toml)
#   BW_WEB_VERSION        (optional)  bw_web_builds tag (default below); "latest" to track upstream
#   KV_ID                 (optional)  ATTACHMENTS_KV namespace id; enables the KV binding
#   R2_NAME               (optional)  R2 bucket name; enables the ATTACHMENTS_BUCKET binding
#   SKIP_INSTALL          (optional)  "1" to skip `npm ci` (the caller already installed)
#
set -euo pipefail

# Run from the repository root regardless of where the script is invoked.
cd "$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"

BW_WEB_VERSION="${BW_WEB_VERSION:-v2026.6.4}"

step() { printf '\n\033[1m=== %s ===\033[0m\n' "$1"; }

# ---------------------------------------------------------------------------
if [ "${SKIP_INSTALL:-0}" = "1" ]; then
  # GitHub Actions installs first (it needs dependencies for the test step).
  step "Node dependencies -- SKIPPED (SKIP_INSTALL=1)"
else
  step "Node dependencies (npm ci)"
  npm ci
fi

# ---------------------------------------------------------------------------
step "PBKDF2 WebAssembly module (asc)"
# wasm/pbkdf2.wasm is committed, but rebuilding here guarantees the binary
# matches wasm/pbkdf2.ts. The module is what makes 600k PBKDF2 iterations fit in
# the Worker CPU budget, so a stale artifact is a correctness risk.
npm run build:wasm

# ---------------------------------------------------------------------------
step "Web Vault frontend (bw_web_builds ${BW_WEB_VERSION})"
# The frontend is not committed (see .gitignore); download it at build time into
# public/web-vault, which wrangler.toml serves via [assets].
BW_WEB_VERSION="${BW_WEB_VERSION}" node tools/fetch-web-vault.mjs

# ---------------------------------------------------------------------------
step "Configure wrangler.toml"
if [ -z "${D1_DATABASE_ID:-}" ]; then
  echo "ERROR: D1_DATABASE_ID build variable is not set" >&2
  exit 1
fi
# wrangler does not expand ${VAR} in wrangler.toml, so substitute it here.
# This edit persists to the Deploy phase (build and deploy share the workspace).
if grep -q 'REPLACE_WITH_YOUR_D1_DATABASE_ID' wrangler.toml; then
  sed -i "s|REPLACE_WITH_YOUR_D1_DATABASE_ID|${D1_DATABASE_ID}|g" wrangler.toml
  echo "Substituted the D1 database id in wrangler.toml"
else
  echo "wrangler.toml already carries a D1 database id; leaving it untouched"
fi

if [ -n "${R2_NAME:-}" ]; then
  echo "Enabling R2 bucket binding -> ${R2_NAME}"
  {
    echo ''
    echo '[[r2_buckets]]'
    echo 'binding = "ATTACHMENTS_BUCKET"'
    echo "bucket_name = \"${R2_NAME}\""
  } >> wrangler.toml
fi

# Attachments are optional. Without an id the KV binding is skipped by wrangler
# and every attachment endpoint answers "Attachments are not enabled", so allow
# the id to come from a build variable instead of a hand edit.
if [ -n "${KV_ID:-}" ]; then
  if grep -q '# id = "REPLACE_WITH_YOUR_KV_NAMESPACE_ID"' wrangler.toml; then
    echo "Enabling KV namespace binding -> ${KV_ID}"
    sed -i "s|# id = \"REPLACE_WITH_YOUR_KV_NAMESPACE_ID\"|id = \"${KV_ID}\"|" wrangler.toml
  else
    echo "wrangler.toml already carries a KV namespace id; leaving it untouched"
  fi
fi

# ---------------------------------------------------------------------------
step "Typecheck (tsc --noEmit)"
npm run typecheck

step "Bundle check (wrangler deploy --dry-run)"
# Fail in the build phase rather than mid-deploy on a bundling error.
npx wrangler deploy --dry-run --outdir .wrangler/build

step "Build complete"
echo "Next, the Deploy command runs: bash scripts/cf-deploy.sh"
