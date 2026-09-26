#!/usr/bin/env node
/** Test runner (§175): Go unit tests + fixture scan verification (§136-137). */
import { execSync } from 'node:child_process';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const go = process.env.GO_BIN || 'go';

console.log('[test] Go unit + integration tests...');
try {
  execSync(`${go} -C ${resolve(root, 'native')} test -timeout 180s ./...`, { stdio: 'inherit' });
} catch {
  console.error('[test] FAIL: go tests failed');
  process.exit(1);
}

console.log('[test] go vet...');
try {
  execSync(`${go} -C ${resolve(root, 'native')} vet ./...`, { stdio: 'inherit' });
} catch {
  console.error('[test] FAIL: go vet failed');
  process.exit(1);
}

console.log('[test] All tests passed.');
