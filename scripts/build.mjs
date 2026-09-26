#!/usr/bin/env node
/** Build the extension (vite) + verify output integrity (§175 build). */
import { execSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const extDir = resolve(root, 'extension');

console.log('[build] Building Chrome extension (vite + typescript)...');
execSync('npx vite build', { cwd: extDir, stdio: 'inherit' });

// verify expected outputs exist and manifest is valid JSON with pinned key
const dist = resolve(extDir, 'dist');
const required = ['manifest.json', 'background.js', 'popup.html', 'dashboard.html', 'icons/icon128.png'];
for (const f of required) {
  if (!existsSync(resolve(dist, f))) {
    console.error(`[build] FAIL: missing ${f} in extension/dist`);
    process.exit(1);
  }
}
const manifest = JSON.parse(readFileSync(resolve(dist, 'manifest.json'), 'utf8'));
if (manifest.manifest_version !== 3) {
  console.error('[build] FAIL: manifest_version must be 3');
  process.exit(1);
}
if (!manifest.key) {
  console.error('[build] FAIL: pinned key missing — extension ID would not be stable');
  process.exit(1);
}
console.log(`[build] Extension OK — stable ID: ${idFromKey(manifest.key)}`);
console.log('[build] Run `npm run lint` next to verify no remote resources.');

function idFromKey(b64) {
  const spki = Buffer.from(b64, 'base64');
  const hash = createHash('sha256').update(spki).digest('hex');
  return [...hash.slice(0, 32)].map((h) => String.fromCharCode(97 + parseInt(h, 16))).join('');
}
