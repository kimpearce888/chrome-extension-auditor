#!/usr/bin/env node
/**
 * Final packaging (§176, §175): builds the extension, cross-compiles the
 * Windows x64 scanner, runs the offline/local-only lint, self-audit and
 * fixture verification, then assembles the distribution ZIP.
 */
import { execSync } from 'node:child_process';
import { cpSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync, readdirSync } from 'node:fs';
import { resolve, dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const win = process.argv.includes('--windows');
const pkgName = 'Local-Chrome-Extension-Auditor';
const staging = resolve(root, 'package', pkgName);

console.log('[package] 1/6 Building extension...');
execSync('node scripts/build.mjs', { cwd: root, stdio: 'inherit' });

console.log('[package] 2/6 Linting for non-local references (§101)...');
execSync('LINT_DIST=1 node scripts/lint.mjs', { cwd: root, stdio: 'inherit', shell: process.platform === 'win32' ? 'cmd.exe' : undefined });

console.log('[package] 3/6 Running tests...');
execSync('node scripts/test.mjs', { cwd: root, stdio: 'inherit' });

console.log('[package] 4/6 Cross-compiling native scanner (windows/amd64)...');
rmSync(resolve(root, 'native/scanner.exe'), { force: true });
execSync('go -C native build -trimpath -ldflags "-s -w" -o scanner.exe .', { cwd: root, stdio: 'inherit' });
if (!existsSync(resolve(root, 'native/scanner.exe'))) {
  console.error('[package] scanner.exe missing');
  process.exit(1);
}

console.log('[package] 5/6 Self-audit of the auditor (§138)...');
execSync('node scripts/self-scan.mjs', { cwd: root, stdio: 'inherit' });

console.log('[package] 6/6 Assembling package...');
rmSync(resolve(root, 'package'), { recursive: true, force: true });
mkdirSync(staging, { recursive: true });

// §176 layout
mkdirSync(join(staging, 'extension'), { recursive: true });
mkdirSync(join(staging, 'native'), { recursive: true });
mkdirSync(join(staging, 'installer'), { recursive: true });
mkdirSync(join(staging, 'reports'), { recursive: true });
mkdirSync(join(staging, 'docs'), { recursive: true });

cpSync(resolve(root, 'extension/dist'), join(staging, 'extension'), { recursive: true });
cpSync(resolve(root, 'native/scanner.exe'), join(staging, 'native/scanner.exe'));
cpSync(resolve(root, 'installer/Install.bat'), join(staging, 'Install.bat'));
cpSync(resolve(root, 'installer/Uninstall.bat'), join(staging, 'Uninstall.bat'));
cpSync(resolve(root, 'installer/Diagnose.bat'), join(staging, 'Diagnose.bat'));
cpSync(resolve(root, 'installer/install.ps1'), join(staging, 'installer/install.ps1'));
cpSync(resolve(root, 'installer/uninstall.ps1'), join(staging, 'installer/uninstall.ps1'));
for (const doc of ['README.md', 'PRIVACY.md', 'SECURITY.md', 'LIMITATIONS.md']) {
  cpSync(resolve(root, 'docs', doc), join(staging, doc));
}
cpSync(resolve(root, 'docs/README.md'), join(staging, 'README.txt'));
writeFileSync(join(staging, 'reports/README.txt'),
  'Exported reports (JSON/CSV/HTML/PDF) are written by the native scanner to its own data directory\n' +
  '(%LOCALAPPDATA%\\LocalExtensionAuditor\\reports). This folder documents that fact; the ZIP itself\n' +
  'stays read-only so it can be re-verified at any time.\n');

// exclude node_modules/.git/temps per §176 — nothing of those is copied above.

const zipName = 'Local-Chrome-Extension-Auditor-Windows.zip';
rmSync(resolve(root, 'package', zipName), { force: true });
execSync(`cd package && zip -r -q ${zipName} ${pkgName}`, { cwd: root, stdio: 'inherit', shell: process.platform === 'win32' ? 'cmd.exe' : undefined });

console.log(`[package] DONE: package/${zipName}`);
console.log('[package] Final layout:');
execSync(`cd package && find ${pkgName} -maxdepth 2 | sort`, { cwd: root, stdio: 'inherit', shell: process.platform === 'win32' ? 'cmd.exe' : undefined });
