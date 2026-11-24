/**
 * Compare two golden captures case by case.
 *
 *   node tools/diff-golden.mjs tests/golden/http.json tests/golden/http.ts.json
 *
 * JSON object key order is not part of the contract (Rust itself uses two
 * different orders depending on the serialization path), so keys are sorted
 * before comparing. Volatile values were already normalized by the capture.
 */
import { readFileSync } from 'node:fs';

function sortKeys(value) {
  if (Array.isArray(value)) return value.map(sortKeys);
  if (value !== null && typeof value === 'object') {
    const out = {};
    for (const key of Object.keys(value).sort()) out[key] = sortKeys(value[key]);
    return out;
  }
  return value;
}

function maskAccessId(value) {
  if (Array.isArray(value)) return value.map(maskAccessId);
  if (value !== null && typeof value === 'object') {
    const out = {};
    for (const [key, child] of Object.entries(value)) {
      out[key] = key === 'accessId' ? '<accessId>' : maskAccessId(child);
    }
    return out;
  }
  return value;
}

/** Drop values that legitimately differ between environments. */
function scrub(name, body) {
  if (name === 'revision-date') return '<timestamp>';
  const value = maskAccessId(body);
  if (name === 'config' && value !== null && typeof value === 'object') {
    delete value.environment;
  }
  if (value !== null && typeof value === 'object' && value.domains) {
    delete value.domains.globalEquivalentDomains;
  }
  return value;
}

function diffPaths(a, b, path = '', out = []) {
  if (out.length >= 40) return out;

  const ta = a === null ? 'null' : Array.isArray(a) ? 'array' : typeof a;
  const tb = b === null ? 'null' : Array.isArray(b) ? 'array' : typeof b;
  if (ta !== tb) {
    out.push(`${path}: type ${ta} vs ${tb}`);
    return out;
  }

  if (ta === 'array') {
    if (a.length !== b.length) out.push(`${path}: length ${a.length} vs ${b.length}`);
    for (let i = 0; i < Math.min(a.length, b.length); i += 1) {
      diffPaths(a[i], b[i], `${path}[${i}]`, out);
    }
    return out;
  }

  if (ta === 'object') {
    const keys = new Set([...Object.keys(a), ...Object.keys(b)]);
    for (const key of keys) {
      if (!(key in a)) out.push(`${path}.${key}: missing on rust side`);
      else if (!(key in b)) out.push(`${path}.${key}: missing on ts side`);
      else diffPaths(a[key], b[key], `${path}.${key}`, out);
    }
    return out;
  }

  if (a !== b) out.push(`${path}: ${JSON.stringify(a)} vs ${JSON.stringify(b)}`);
  return out;
}

const [rustPath, tsPath] = process.argv.slice(2);
const rust = JSON.parse(readFileSync(rustPath, 'utf8'));
const ts = JSON.parse(readFileSync(tsPath, 'utf8'));

const byName = new Map(ts.cases.map((c) => [c.name, c]));
let same = 0;
const failures = [];

for (const rustCase of rust.cases) {
  const tsCase = byName.get(rustCase.name);
  if (!tsCase) {
    failures.push({ name: rustCase.name, issues: ['missing from TS capture'] });
    continue;
  }

  const issues = [];
  if (rustCase.response.status !== tsCase.response.status) {
    issues.push(`status ${rustCase.response.status} vs ${tsCase.response.status}`);
  }
  const bodyIssues = diffPaths(
    sortKeys(scrub(rustCase.name, rustCase.response.body)),
    sortKeys(scrub(tsCase.name, tsCase.response.body)),
    'body',
  );
  issues.push(...bodyIssues);

  if (issues.length === 0) same += 1;
  else failures.push({ name: rustCase.name, issues });
}

console.log(`cases: ${rust.cases.length} | identical: ${same} | different: ${failures.length}\n`);
for (const failure of failures) {
  console.log(`✗ ${failure.name}`);
  for (const issue of failure.issues.slice(0, 8)) console.log(`    ${issue}`);
  if (failure.issues.length > 8) console.log(`    … ${failure.issues.length - 8} more`);
}
