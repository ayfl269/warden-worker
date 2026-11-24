#!/usr/bin/env node
/**
 * Download the Bitwarden Web Vault frontend into `public/web-vault`.
 *
 * The frontend is a prebuilt Angular bundle published by the Vaultwarden project
 * as `bw_web_builds` releases. It is *not* committed (see `.gitignore`): ~40 MB
 * compressed, ~80 MB extracted, and this repository never edits it. `wrangler.toml`
 * serves it as Cloudflare static assets straight out of `public/web-vault`.
 *
 * Usage:
 *   node tools/fetch-web-vault.mjs                 # default pinned tag
 *   node tools/fetch-web-vault.mjs --force         # re-download even if present
 *   node tools/fetch-web-vault.mjs --version latest
 *   BW_WEB_VERSION=v2026.11.0 node tools/fetch-web-vault.mjs
 *
 * Slow or filtered network? Node's fetch only honours a proxy when told to:
 *   HTTP_PROXY=http://127.0.0.1:7890 HTTPS_PROXY=http://127.0.0.1:7890 \
 *     NODE_USE_ENV_PROXY=1 node tools/fetch-web-vault.mjs --force
 *
 * The script is idempotent: it exits immediately once a complete tree has been
 * extracted (tracked by `public/.web-vault-version`), so `npm run dev` and
 * `npm run deploy` stay cheap after the first run. Pass `--force` to switch tags.
 *
 * Steps:
 *   1. resolve the tag (optionally "latest" via the GitHub API),
 *   2. download the tarball, resuming across dropped connections,
 *   3. verify it against the release's published `sha256sums.txt`,
 *   4. extract it into `public/` and delete `*.map` files,
 *   5. copy our UI override to `public/web-vault/css/vaultwarden.css`.
 */

import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { createReadStream, createWriteStream, existsSync } from 'node:fs';
import { cp, mkdir, readdir, rm, stat, writeFile } from 'node:fs/promises';
import path from 'node:path';
import process from 'node:process';
import { Readable } from 'node:stream';
import { pipeline } from 'node:stream/promises';

const DEFAULT_VERSION = 'v2026.10.1';
const RELEASES_API = 'https://api.github.com/repos/dani-garcia/bw_web_builds/releases';
const REPO_ROOT = path.resolve(import.meta.dirname, '..');
const PUBLIC_DIR = path.join(REPO_ROOT, 'public');
const TARGET_DIR = path.join(PUBLIC_DIR, 'web-vault');
// Written only after a complete download + extraction. `index.html` alone is not
// a safe marker: an interrupted extraction leaves one behind.
const MARKER_FILE = path.join(PUBLIC_DIR, '.web-vault-version');
const CSS_OVERRIDE = path.join(PUBLIC_DIR, 'css', 'vaultwarden.css');

function parseArgs(argv) {
  const options = { force: false, version: process.env.BW_WEB_VERSION ?? DEFAULT_VERSION };
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === '--force' || arg === '-f') {
      options.force = true;
    } else if (arg === '--version' || arg === '-v') {
      const value = argv[index + 1];
      if (value === undefined) throw new Error('--version requires a tag');
      options.version = value;
      index += 1;
    } else if (arg === '--help' || arg === '-h') {
      console.log('usage: node tools/fetch-web-vault.mjs [--force] [--version <tag|latest>]');
      process.exit(0);
    } else {
      throw new Error(`unknown argument: ${arg}`);
    }
  }
  return options;
}

async function resolveTag(version) {
  if (version !== 'latest') return version;

  const response = await fetch(`${RELEASES_API}/latest`, {
    headers: { accept: 'application/vnd.github+json', 'user-agent': 'warden-worker' },
  });
  if (!response.ok) {
    throw new Error(`GitHub API ${response.status} while resolving the latest release`);
  }
  const body = await response.json();
  if (typeof body.tag_name !== 'string' || body.tag_name.length === 0) {
    throw new Error('GitHub API response did not contain tag_name');
  }
  return body.tag_name;
}

async function downloadOnce(url, destination) {
  // Resume a partial file: the tarball is ~40 MB and GitHub release downloads are
  // not always fast or reliable, so a dropped connection must not mean starting
  // over.
  const existing = existsSync(destination) ? (await stat(destination)).size : 0;
  const headers = { 'user-agent': 'warden-worker' };
  if (existing > 0) {
    headers.range = `bytes=${existing}-`;
    console.log(`  resuming at ${formatBytes(existing)}`);
  }

  const response = await fetch(url, { headers, redirect: 'follow' });
  if (response.status === 416) {
    // Nothing left to send: the local file already holds the whole artifact.
    return { complete: true, size: existing };
  }
  if (!response.ok || response.body === null) {
    throw new Error(`GET ${url} -> ${response.status} ${response.statusText}`);
  }
  // A server that ignores Range answers 200; the partial file must be discarded.
  const resuming = existing > 0 && response.status === 206;
  if (existing > 0 && !resuming) {
    console.log('  server ignored the range request, restarting from zero');
  }

  // Stream straight to disk: buffering 40 MB in memory would waste RSS and hide
  // progress.
  const expected = Number(response.headers.get('content-length') ?? '0');
  const alreadyOnDisk = resuming ? existing : 0;
  const total = expected > 0 ? alreadyOnDisk + expected : 0;
  let received = 0;
  let reported = 0;
  const body = response.body.pipeThrough(
    new TransformStream({
      transform(chunk, controller) {
        received += chunk.byteLength;
        // Report at most every 8 MiB so build logs stay readable.
        if (received - reported >= 8 * 1024 * 1024) {
          reported = received;
          const done = alreadyOnDisk + received;
          const share = total > 0 ? ` (${Math.floor((done / total) * 100)}%)` : '';
          console.log(`  ${formatBytes(done)}${share}`);
        }
        controller.enqueue(chunk);
      },
    }),
  );

  await pipeline(
    Readable.fromWeb(body),
    createWriteStream(destination, { flags: resuming ? 'a' : 'w' }),
  );

  const size = (await stat(destination)).size;
  return { complete: total === 0 || size >= total, size, total };
}

/**
 * Download `url` to `destination`, resuming across dropped connections.
 *
 * A truncated transfer does not necessarily raise an error: the response body
 * simply ends, and `pipeline` resolves. The only reliable completeness check is
 * the byte count against the advertised total, so the loop retries until the
 * file reaches it.
 */
async function download(url, destination) {
  const maxAttempts = 5;
  let lastSize = 0;
  for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
    const result = await downloadOnce(url, destination);
    if (result.complete) return result.size;

    lastSize = result.size;
    console.log(
      `  transfer ended early at ${formatBytes(result.size)} of ${formatBytes(result.total)}` +
        ` (attempt ${attempt}/${maxAttempts})`,
    );
  }
  throw new Error(
    `download stopped at ${formatBytes(lastSize)} after ${maxAttempts} attempts; ` +
      'delete public/bw_web_*.tar.gz to start over',
  );
}

async function sha256File(file) {
  const hash = createHash('sha256');
  await pipeline(createReadStream(file), hash);
  return hash.digest('hex');
}

/**
 * Look up the published SHA-256 for `asset` in the release's `sha256sums.txt`.
 *
 * Returns null when the sums file is unavailable, so a missing checksum degrades
 * to a plain download instead of failing the build.
 */
async function publishedChecksum(releaseBase, asset) {
  try {
    const response = await fetch(`${releaseBase}/sha256sums.txt`, {
      headers: { 'user-agent': 'warden-worker' },
      redirect: 'follow',
    });
    if (!response.ok) return null;
    const body = await response.text();
    for (const line of body.split('\n')) {
      const match = /^([0-9a-f]{64})\s+\*?(.+)$/i.exec(line.trim());
      if (match !== null && match[2] === asset) return match[1].toLowerCase();
    }
  } catch {
    // Network hiccup while fetching the sums file: fall through to no checksum.
  }
  return null;
}

function extract(tarball, into) {
  // `tar` ships with Linux (GNU tar) and Windows 10+ (bsdtar); both accept -xzf.
  // stdio is inherited on purpose: piping a child's stdio is restricted in some
  // sandboxes and would surface as EPERM rather than a useful tar error.
  const result = spawnSync('tar', ['-xzf', tarball, '-C', into], { stdio: 'inherit' });
  if (result.error !== undefined) {
    throw new Error(`failed to run tar: ${result.error.message}`);
  }
  if (result.status !== 0) {
    throw new Error(`tar exited with status ${result.status}`);
  }
}

/** Recursively delete files whose name ends with `.map`; returns the count. */
async function deleteSourceMaps(directory) {
  let removed = 0;
  const entries = await readdir(directory, { withFileTypes: true });
  for (const entry of entries) {
    const full = path.join(directory, entry.name);
    if (entry.isDirectory()) {
      removed += await deleteSourceMaps(full);
    } else if (entry.isFile() && entry.name.endsWith('.map')) {
      await rm(full, { force: true });
      removed += 1;
    }
  }
  return removed;
}

async function measure(directory) {
  let files = 0;
  let bytes = 0;
  const entries = await readdir(directory, { withFileTypes: true });
  for (const entry of entries) {
    const full = path.join(directory, entry.name);
    if (entry.isDirectory()) {
      const nested = await measure(full);
      files += nested.files;
      bytes += nested.bytes;
    } else if (entry.isFile()) {
      files += 1;
      bytes += (await stat(full)).size;
    }
  }
  return { files, bytes };
}

function formatBytes(bytes) {
  return `${(bytes / 1024 / 1024).toFixed(1)} MiB`;
}

/**
 * Download `url` into `tarball` and verify it against the published checksum.
 *
 * A partial file left behind by an interrupted run is normally safe to resume,
 * but it can also be corrupt (a killed process, a proxy that rewrote bytes).
 * The checksum is the only way to tell, so a mismatch discards the file and
 * downloads once more from zero before giving up.
 */
async function downloadVerified(url, releaseBase, asset, tarball) {
  const expected = await publishedChecksum(releaseBase, asset);

  for (let attempt = 1; attempt <= 2; attempt += 1) {
    const size = await download(url, tarball);
    console.log(`  received ${formatBytes(size)}`);

    if (expected === null) {
      console.log('  no published sha256 found, skipping verification');
      return;
    }

    const actual = await sha256File(tarball);
    if (actual === expected) {
      console.log('  sha256 verified');
      return;
    }

    await rm(tarball, { force: true });
    if (attempt === 2) {
      throw new Error(`checksum mismatch for ${asset}: expected ${expected}, got ${actual}`);
    }
    console.log('  checksum mismatch on the partial file, starting over from zero');
  }
}

async function main() {
  const options = parseArgs(process.argv.slice(2));
  const indexHtml = path.join(TARGET_DIR, 'index.html');

  if (!options.force && existsSync(indexHtml) && existsSync(MARKER_FILE)) {
    const { files } = await measure(TARGET_DIR);
    console.log(`web-vault already present (${files} files) - pass --force to re-download`);
    return;
  }

  const tag = await resolveTag(options.version);
  const asset = `bw_web_${tag}.tar.gz`;
  const releaseBase = `https://github.com/dani-garcia/bw_web_builds/releases/download/${tag}`;
  const url = `${releaseBase}/${asset}`;

  console.log(`web-vault: ${tag}`);
  console.log(`  downloading ${url}`);
  await mkdir(PUBLIC_DIR, { recursive: true });
  const tarball = path.join(PUBLIC_DIR, asset);
  await downloadVerified(url, releaseBase, asset, tarball);

  // A stale tree would leave files from a previous tag behind (e.g. hashed
  // chunk names that no longer exist in index.html), so always start clean.
  await rm(TARGET_DIR, { recursive: true, force: true });
  console.log('  extracting');
  try {
    extract(tarball, PUBLIC_DIR);
    if (!existsSync(indexHtml)) {
      throw new Error(`expected ${path.relative(REPO_ROOT, indexHtml)} after extracting ${asset}`);
    }
  } catch (error) {
    // Never leave a half-extracted tree behind: `index.html` existing is how the
    // next run decides the frontend is already in place.
    await rm(TARGET_DIR, { recursive: true, force: true });
    await rm(tarball, { force: true });
    await rm(MARKER_FILE, { force: true });
    throw error;
  }
  await rm(tarball, { force: true });

  const removed = await deleteSourceMaps(TARGET_DIR);
  console.log(`  removed ${removed} source map(s)`);

  // Lightweight UI override: hides features this backend does not implement.
  if (existsSync(CSS_OVERRIDE)) {
    await mkdir(path.join(TARGET_DIR, 'css'), { recursive: true });
    await cp(CSS_OVERRIDE, path.join(TARGET_DIR, 'css', 'vaultwarden.css'));
    console.log('  applied css/vaultwarden.css override');
  }

  const { files, bytes } = await measure(TARGET_DIR);
  await writeFile(MARKER_FILE, `${tag}\n`);
  console.log(`web-vault ready: ${files} files, ${formatBytes(bytes)} in public/web-vault`);
}

main().catch((error) => {
  console.error(`fetch-web-vault: ${error.message}`);
  process.exit(1);
});
