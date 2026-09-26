import { defineConfig } from 'vite';
import { resolve } from 'path';

/**
 * Chrome extension build (§6): Vite + TypeScript, multi-entry, stable output
 * names so manifest references never break. No remote resources are bundled
 * (§141) — the linter verifies this after every build.
 *
 * root=src so HTML entries land at the dist root (dashboard.html, popup.html)
 * exactly where manifest.json references them.
 */
export default defineConfig({
  root: resolve(__dirname, 'src'),
  publicDir: resolve(__dirname, 'public'),
  build: {
    outDir: resolve(__dirname, 'dist'),
    emptyOutDir: true,
    target: 'chrome116',
    // Vite's preload polyfill injects a fetch() call; disabled so the built
    // extension contains ZERO network APIs (§101 verified by scripts/lint.mjs).
    modulePreload: false,
    rollupOptions: {
      input: {
        background: resolve(__dirname, 'src/background.ts'),
        popup: resolve(__dirname, 'src/popup.html'),
        dashboard: resolve(__dirname, 'src/dashboard.html'),
      },
      output: {
        entryFileNames: '[name].js',
        chunkFileNames: 'chunks/[name].js',
        assetFileNames: 'assets/[name][extname]',
      },
    },
  },
});
