#!/usr/bin/env node
/**
 * Demo harness (development only).
 *
 * Serves the REAL built dashboard against the REAL scanner binary, pointed at
 * a synthetic Chrome "User Data" tree assembled from the bundled test
 * fixtures. Used for UI development and for the screenshots in the README —
 * everything you see in the dashboard is genuine analyzer output; only the
 * browser profile is synthetic (clearly labelled in the page).
 *
 *   node scripts/demo.mjs [--port 4318] [--fresh] [--no-warmup]
 *
 * Requires: built extension (npm run build), Go toolchain on PATH.
 */
import { spawn, execSync } from 'node:child_process';
import { cpSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { dirname, extname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const DEMO = join(root, '.demo');
const DIST = join(root, 'extension', 'dist');
const FIXTURES = join(root, 'fixtures');

// ---------- CLI args ----------
const args = process.argv.slice(2);
const portIdx = args.indexOf('--port');
const port = portIdx >= 0 ? Number(args[portIdx + 1]) : 4318;
const fresh = args.includes('--fresh');
const warmup = !args.includes('--no-warmup');

// ---------- synthetic profile plan ----------
// location codes (as the scanner interprets them):
//   0 = Web Store, 1 = external/prefs (sideloaded), 3 = unpacked/developer
const PLAN = [
  {
    profile: 'Default', profileName: 'Work',
    installs: [
      { fixture: '01-simple', location: 0, state: 1 },
      { fixture: '04-content-heavy', location: 0, state: 1 },
      { fixture: '05-permission-heavy', location: 0, state: 1 },
      { fixture: '06-network-heavy', location: 0, state: 1 },
      { fixture: '07-timer-heavy', location: 0, state: 1 },
      { fixture: '09-native-messaging', location: 3, state: 1 },
      { fixture: '12-obfuscated', location: 1, state: 1 },
      { fixture: '14-legacy-mv2', location: 0, state: 0, disableReasons: [11] },
    ],
  },
  {
    profile: 'Profile 1', profileName: 'Personal',
    installs: [
      { fixture: '03-minified', location: 0, state: 1 },
      { fixture: '05-permission-heavy', location: 0, state: 1 }, // same ext, second profile
      { fixture: '08-observer-heavy', location: 0, state: 1 },
      { fixture: '13-large-package', location: 0, state: 1 },
    ],
  },
];

// Deterministic Chrome-style extension ID (a-p alphabet) from a name.
function extId(name) {
  let h = 0x811c9dc5n;
  for (const ch of Buffer.from(name, 'utf8')) {
    h ^= BigInt(ch);
    h = (h * 0x01000193n) & 0xffffffffn;
  }
  let id = '';
  for (let i = 0; i < 32; i++) {
    const nib = Number((h >> BigInt(i % 28)) & 0xfn);
    id += String.fromCharCode(97 + nib); // a..p
    h = (h ^ (h << 13n)) & 0xffffffffn;
    h = (h ^ (h >> 7n)) & 0xffffffffn;
  }
  return id;
}

function readManifest(fixture) {
  return JSON.parse(readFileSync(join(FIXTURES, fixture, 'manifest.json'), 'utf8'));
}

function buildProfile() {
  const userData = join(DEMO, 'chrome', 'User Data');
  if (existsSync(userData)) rmSync(userData, { recursive: true, force: true });
  mkdirSync(userData, { recursive: true });

  const infoCache = {};
  for (const p of PLAN) infoCache[p.profile] = { name: p.profileName };
  writeFileSync(join(userData, 'Local State'), JSON.stringify({
    profile: { info_cache: infoCache },
  }, null, 2));

  for (const p of PLAN) {
    const pdir = join(userData, p.profile);
    mkdirSync(pdir, { recursive: true });
    const settings = {};
    for (const inst of p.installs) {
      const m = readManifest(inst.fixture);
      const id = extId(inst.fixture);
      const ver = m.version || '1.0.0';
      const dest = join(pdir, 'Extensions', id, ver);
      cpSync(join(FIXTURES, inst.fixture), dest, { recursive: true });
      settings[id] = {
        state: inst.state,
        location: inst.location,
        path: `${p.profile}/Extensions/${id}/${ver}`,
        manifest: { name: m.name, version: ver },
        disable_reasons: inst.disableReasons || [],
      };
    }
    writeFileSync(join(pdir, 'Preferences'), JSON.stringify({
      extensions: { settings },
    }, null, 2));
  }
  return userData;
}

// Mutation applied between scans so the snapshot-diff ("compare") view has a
// real change to show: permission-heavy gets a new version with broader
// permissions in the Work profile.
function mutatePermissionHeavy(newVersion, addedPermissions) {
  const p = PLAN[0];
  const inst = p.installs.find((i) => i.fixture === '05-permission-heavy');
  const id = extId(inst.fixture);
  const src = join(FIXTURES, inst.fixture);
  const m = readManifest(inst.fixture);
  m.version = newVersion;
  m.permissions = [...(m.permissions || []), ...addedPermissions];
  const dest = join(DEMO, 'chrome', 'User Data', p.profile, 'Extensions', id, newVersion);
  cpSync(src, dest, { recursive: true });
  writeFileSync(join(dest, 'manifest.json'), JSON.stringify(m, null, 2));

  // point preferences at the new version
  const prefPath = join(DEMO, 'chrome', 'User Data', p.profile, 'Preferences');
  const prefs = JSON.parse(readFileSync(prefPath, 'utf8'));
  prefs.extensions.settings[id].path = `${p.profile}/Extensions/${id}/${newVersion}`;
  prefs.extensions.settings[id].manifest = { name: m.name, version: m.version };
  writeFileSync(prefPath, JSON.stringify(prefs, null, 2));
}

function managementInventory() {
  const inv = [];
  const seen = new Set();
  for (const p of PLAN) {
    for (const inst of p.installs) {
      const id = extId(inst.fixture);
      if (seen.has(id)) continue;
      seen.add(id);
      const m = readManifest(inst.fixture);
      inv.push({
        id, name: m.name || inst.fixture, version: m.version || '1.0.0',
        enabled: inst.state === 1,
        installType: inst.location === 0 ? 'normal' : inst.location === 1 ? 'sideload' : 'development',
        type: 'extension', description: m.description || '',
        mayDisable: true, disabledReason: inst.state === 1 ? undefined : 'Disabled for unsupported manifest version',
      });
    }
  }
  return inv;
}

// ---------- scanner process + framed bridge ----------
function buildScanner() {
  const bin = join(DEMO, 'scanner-demo');
  if (fresh || !existsSync(bin)) {
    execSync(`go build -o "${bin}" .`, { cwd: join(root, 'native'), stdio: 'inherit' });
  }
  return bin;
}

const pending = new Map(); // requestId -> { msgs, resolve }
let scanner = null;
let readBuf = Buffer.alloc(0);

function frame(obj) {
  const data = Buffer.from(JSON.stringify(obj), 'utf8');
  const head = Buffer.alloc(4);
  head.writeUInt32LE(data.length, 0);
  return Buffer.concat([head, data]);
}

function startScanner(userData) {
  scanner = spawn(buildScanner(), [], {
    env: {
      ...process.env,
      CEA_CHROME_USER_DATA: userData,
      CEA_DATA_DIR: join(DEMO, 'data'),
    },
    stdio: ['pipe', 'pipe', 'inherit'],
  });
  scanner.stdout.on('data', (chunk) => {
    readBuf = Buffer.concat([readBuf, chunk]);
    for (;;) {
      if (readBuf.length < 4) return;
      const len = readBuf.readUInt32LE(0);
      if (readBuf.length < 4 + len) return;
      const msg = JSON.parse(readBuf.subarray(4, 4 + len).toString('utf8'));
      readBuf = readBuf.subarray(4 + len);
      const p = pending.get(msg.requestId);
      if (!p) continue;
      p.msgs.push(msg);
      if (!msg.event) { // final response for this request
        pending.delete(msg.requestId);
        p.resolve(p.msgs);
      }
    }
  });
  return new Promise((res, rej) => {
    scanner.once('spawn', res);
    scanner.once('error', rej);
  });
}

// The browser's requestId is forwarded VERBATIM so response frames match the
// UI's pending-request map (native.ts demuxes on requestId).
function request(requestId, action, options) {
  return new Promise((resolve, reject) => {
    const entry = { msgs: [], resolve };
    pending.set(requestId, entry);
    const timer = setTimeout(() => {
      if (pending.has(requestId)) {
        pending.delete(requestId);
        reject(new Error(`bridge timeout: ${action}`));
      }
    }, 120_000);
    const wrapped = (msgs) => { clearTimeout(timer); resolve(msgs); };
    entry.resolve = wrapped;
    scanner.stdin.write(frame({ requestId, action, options }));
  });
}

// ---------- demo page (real dashboard + chrome shim) ----------
const MIME = {
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.html': 'text/html; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.png': 'image/png',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon',
  '.map': 'application/json',
};

const SHIM = String.raw`
(function () {
  'use strict';
  // ---- tiny storage shim (persisted to localStorage) ----
  let mem = {};
  try { mem = JSON.parse(localStorage.getItem('cea-demo-store') || '{}'); } catch (e) {}
  const save = () => { try { localStorage.setItem('cea-demo-store', JSON.stringify(mem)); } catch (e) {} };
  const w = window;
  w.chrome = w.chrome || {};
  w.chrome.storage = {
    local: {
      get: async (keys) => {
        const list = Array.isArray(keys) ? keys : [keys];
        const out = {};
        for (const k of list) if (k in mem) out[k] = mem[k];
        return out;
      },
      set: async (obj) => { Object.assign(mem, obj); save(); },
    },
  };
  w.chrome.runtime = {
    lastError: null,
    getManifest: () => ({ manifest_version: 3, name: 'Local Chrome Extension Auditor', version: '1.0.0' }),
    connectNative: function () {
      const listeners = { message: [], disconnect: [] };
      return {
        name: 'com.local.extensionauditor.scanner',
        onMessage: { addListener: (fn) => listeners.message.push(fn) },
        onDisconnect: { addListener: (fn) => listeners.disconnect.push(fn) },
        postMessage: function (msg) {
          fetch('/bridge', {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify(msg),
          }).then((r) => r.json()).then((list) => {
            for (const m of list) for (const fn of listeners.message) fn(m);
          }).catch((err) => {
            for (const fn of listeners.message) {
              fn({ requestId: msg.requestId, success: false, error: { code: 'DEMO_BRIDGE', message: String(err) } });
            }
          });
        },
      };
    },
  };
  w.chrome.management = {
    getAll: function (cb) {
      fetch('/management.json').then((r) => r.json()).then((all) => { if (cb) cb(all); return all; });
    },
  };
  // ---- demo banner (honesty: the profile is synthetic) ----
  document.addEventListener('DOMContentLoaded', () => {
    const b = document.createElement('div');
    b.className = 'demo-banner';
    b.textContent = 'DEMO — real scanner, synthetic browser profile (bundled fixtures)';
    document.body.appendChild(b);
    const s = document.createElement('style');
    s.textContent = '.demo-banner{position:fixed;right:14px;bottom:14px;z-index:99999;background:#1c1917;color:#fbbf24;' +
      'border:1px solid #92400e;border-radius:999px;padding:6px 14px;font:600 11px/1.4 system-ui,sans-serif;' +
      'box-shadow:0 4px 14px rgba(0,0,0,.35);pointer-events:none}';
    document.head.appendChild(s);
  });
})();
`;

function demoPage() {
  const html = readFileSync(join(DIST, 'dashboard.html'), 'utf8');
  return html.replace(
    '<script type="module"',
    '<script src="/demo-shim.js"></script>\n  <script type="module"',
  );
}

// ---------- HTTP server ----------
const server = createServer(async (req, res) => {
  try {
    if (req.method === 'POST' && req.url === '/bridge') {
      const body = await new Promise((resolve) => {
        const chunks = [];
        req.on('data', (c) => chunks.push(c));
        req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
      });
      const { requestId, action, options } = JSON.parse(body);
      const msgs = await request(requestId, action, options || {});
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify(msgs));
      return;
    }
    if (req.url === '/' || req.url === '/index.html' || req.url === '/dashboard.html') {
      res.writeHead(200, { 'content-type': MIME['.html'] });
      res.end(demoPage());
      return;
    }
    if (req.url === '/demo-shim.js') {
      res.writeHead(200, { 'content-type': MIME['.js'] });
      res.end(SHIM);
      return;
    }
    if (req.url === '/management.json') {
      res.writeHead(200, { 'content-type': MIME['.json'] });
      res.end(JSON.stringify(managementInventory()));
      return;
    }
    // static from dist
    const file = join(DIST, req.url.replace(/\.\./g, '').split('?')[0]);
    if (file.startsWith(DIST) && existsSync(file)) {
      res.writeHead(200, { 'content-type': MIME[extname(file)] || 'application/octet-stream' });
      res.end(readFileSync(file));
      return;
    }
    res.writeHead(404, { 'content-type': 'text/plain' });
    res.end('not found');
  } catch (e) {
    res.writeHead(500, { 'content-type': 'text/plain' });
    res.end(String(e && e.stack ? e.stack : e));
  }
});

// ---------- main ----------
async function main() {
  if (!existsSync(DIST)) {
    console.error('[demo] extension/dist missing — run: npm run build');
    process.exit(1);
  }
  mkdirSync(DEMO, { recursive: true });
  const userData = buildProfile();
  console.log('[demo] synthetic profile at', userData);
  await startScanner(userData);
  console.log('[demo] scanner started (pid %s)', scanner.pid);

  if (warmup) {
    console.log('[demo] warm-up scan 1/2 …');
    await request('demo-warmup-1', 'scanAll', { mode: 'standard', chromeVersion: 'demo', managementInventory: [] });
    mutatePermissionHeavy('1.1.0', ['cookies', 'history']);
    console.log('[demo] fixture mutated (permission-heavy 1.0.0 -> 1.1.0, +cookies +history)');
    console.log('[demo] warm-up scan 2/2 …');
    await request('demo-warmup-2', 'scanAll', { mode: 'standard', chromeVersion: 'demo', managementInventory: [] });
    // Second mutation AFTER the warm-ups: the browser's own first scan then
    // becomes the "after" state, so the default two-most-recent comparison
    // (warm-up 2 vs browser scan) shows a real permission/version diff.
    mutatePermissionHeavy('1.2.0', ['downloads', 'tabs']);
    console.log('[demo] fixture mutated again (-> 1.2.0, +downloads +tabs) for live diff demo');
    console.log('[demo] warm-up done — compare/history views have data');
  }

  server.listen(port, '127.0.0.1', () => {
    console.log('[demo] dashboard: http://127.0.0.1:%d/', port);
  });

  const shutdown = () => {
    try { scanner.kill(); } catch (e) {}
    process.exit(0);
  };
  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);
}

main().catch((e) => {
  console.error('[demo] fatal:', e);
  process.exit(1);
});
