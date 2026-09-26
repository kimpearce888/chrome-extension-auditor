#!/usr/bin/env node
/** Self-audit wrapper (§138, npm run scan:self): runs the scanner's
 * --self-audit mode against the built extension. */
import { execSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { platform } from 'node:os';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const dist = resolve(root, 'extension/dist');
if (!existsSync(dist)) {
  console.error('[scan:self] extension/dist not built — run npm run build first');
  process.exit(1);
}
const exe = platform() === 'win32'
  ? resolve(root, 'package/Local-Chrome-Extension-Auditor/native/scanner.exe')
  : 'go';
const args = platform() === 'win32'
  ? [`"${resolve(root, 'package/Local-Chrome-Extension-Auditor/native/scanner.exe')}"`, '--self-audit', `"${dist}"`]
  : ['-C', resolve(root, 'native'), 'run', '.', '--self-audit', dist];
console.log(`[scan:self] ${exe} ${args.join(' ')}`);
try {
  execSync(`${exe} ${args.join(' ')}`, { stdio: 'inherit' });
} catch {
  process.exit(1);
}
