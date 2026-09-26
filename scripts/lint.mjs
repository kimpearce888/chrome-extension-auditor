#!/usr/bin/env node
/**
 * Lint (§139–§141, §101): the auditor must not reference remote resources.
 * Scans extension source AND built output for network indicators; every hit is
 * reported for manual review. Exit code 1 when a non-local reference remains.
 */
import { readFileSync, readdirSync, statSync, existsSync } from 'node:fs';
import { resolve, dirname, join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const targets = [resolve(root, 'extension/src'), resolve(root, 'extension/public')];
if (process.argv.includes('--dist') || process.env.LINT_DIST === '1') {
  targets.push(resolve(root, 'extension/dist'));
}

// Allowed local-only exceptions (documented, reviewed):
const ALLOWED_HOSTS = [
  '127.0.0.1', 'localhost', '[::1]', '::1',
  'chrome-extension://', 'about:blank', 'schema.org',
];
// Documentation strings we intentionally render (privacy page texts):
const TEXT_HINTS = [
  'http://127.0.0.1:1234', // shown as the default local endpoint in UI text
];

const urlRe = /(?:https?|wss?):\/\/[^\s"'`<>()\[\]{}\\]+/g;
const forbidden = [
  { name: 'fetch(', re: /\bfetch\s*\(/g },
  { name: 'XMLHttpRequest', re: /\bnew\s+XMLHttpRequest\b/g },
  { name: 'WebSocket', re: /\bnew\s+WebSocket\b/g },
  { name: 'sendBeacon', re: /\bsendBeacon\s*\(/g },
  { name: 'EventSource', re: /\bnew\s+EventSource\b/g },
];

const telemetryKeywords = ['telemetry', 'analytics', 'sentry', 'segment.io', 'firebase', 'supabase', 'doubleclick', 'googletagmanager', 'openai.com', 'anthropic.com', 'gemini'];

let issues = 0;
let files = 0;

function walk(dir) {
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    const st = statSync(p);
    if (st.isDirectory()) walk(p);
    else if (/\.(ts|js|mjs|html|css|json)$/.test(name)) check(p);
  }
}

function check(p) {
  files++;
  const src = readFileSync(p, 'utf8');
  const rel = relative(root, p);
  for (const m of src.match(urlRe) || []) {
    const clean = m.replace(/[.,;:'"`]+$/, '');
    const hostish = clean.split('://')[1] || '';
    const host = hostish.split(/[/?#]/)[0];
    if (ALLOWED_HOSTS.some((a) => clean.includes(a) || host === a)) continue;
    console.log(`[lint] NON-LOCAL URL ${rel}: ${clean}`);
    issues++;
  }
  for (const f of forbidden) {
    const matches = src.match(f.re) || [];
    for (const _ of matches) {
      // fetch( in extension UI code is only permitted when the argument is the
      // native host — but the extension never fetches; flag everything.
      console.log(`[lint] NETWORK API ${rel}: ${f.name}`);
      issues++;
    }
  }
  const lower = src.toLowerCase();
  for (const kw of telemetryKeywords) {
    let idx = 0;
    while ((idx = lower.indexOf(kw, idx)) !== -1) {
      const ctx = src.slice(Math.max(0, idx - 60), idx + kw.length + 60).replace(/\n/g, ' ');
      const isText = TEXT_HINTS.some((h) => ctx.includes(h));
      console.log(`[lint][review] keyword '${kw}' in ${rel}: ...${ctx}...${isText ? ' (context: documentation text)' : ''}`);
      idx += kw.length;
    }
  }
}

for (const t of targets) {
  if (existsSync(t)) walk(t);
}
console.log(`[lint] Scanned ${files} files under ${targets.map((t) => relative(root, t)).join(', ')}.`);
if (issues > 0) {
  console.error(`[lint] FAIL: ${issues} non-local network reference(s). The auditor must be local-only (§101).`);
  process.exit(1);
}
console.log('[lint] PASS: no non-local network references found.');
