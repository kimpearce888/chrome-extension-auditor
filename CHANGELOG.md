# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project
adheres to [Semantic Versioning](https://semver.org/).

## [1.0.5] - 2026-11-23

### Fixed
- Extension names shown as raw `__MSG_...` placeholders (e.g. Chrome Web Store Payments): locale key lookup is now case-insensitive with an exact-match-first fallback, so `__MSG_APP_NAME__` resolves against lowercase keys like `app_name`.
- Nonsensical or duplicated inventory entries: the extension inventory now merges on-disk installations with management/policy and preferences records into one consistent list — no ghost duplicates, and preferences leftovers whose folder is gone are marked **Not on disk** instead of being analyzed as if present.
- Dashboard list: Chrome built-in components (PDF Viewer, Hangouts services, …) are grouped under a collapsible “Chrome built-in components — part of Chrome, not installed by you” section so the main list shows only what the user actually installed; cards for not-on-disk entries say so explicitly instead of showing empty file counts.
- Dashboard details: status badges and card avatars no longer render broken states for unanalyzed/incomplete reports or missing names (falls back to the extension ID).
- Regression coverage: new `fixes_test.go` suite locks in placeholder-name resolution and inventory merging; full Go test suite passes.

### Changed
- Fresh Linux distribution build: `chrome-extension-auditor-linux-v1.0.5.zip` with rebuilt extension (vite) and both native scanner binaries (x86-64, arm64).

## [1.0.4] - 2026-11-18

### Changed
- Fresh distribution build for Linux: self-contained folder + versioned ZIP (`chrome-extension-auditor-linux-v1.0.4.zip`) with the extension, both native scanner binaries (x86-64 and arm64), installer scripts and docs in one place.
- Version bumped across the board — extension manifest, `package.json` and the Go scanner (`ScannerVersion`) now all report **1.0.4** so the dashboard, `--version` output and scan reports stay consistent.

## [1.0.2] - 2026-11-18

### Fixed
- Linux OS version in scan reports now shows the real distro (e.g. "Ubuntu 24.04 LTS") by reading `PRETTY_NAME` from `/etc/os-release`, instead of "Not available".
- Chrome/Chromium version is now detected as a fallback when the extension does not send it (queries the local browser binary with `--version`), so protocol-level scans report real metadata.
- Single-extension scan history records now store Chrome version and OS version.
- Native host installation no longer depends on `/tmp` (cleared on reboot): the installer copies the scanner binary into `~/.local/share/LocalExtensionAuditor/scanner-v1.0.2/` and registers that persistent path for both Chrome and Chromium, preserving existing scan history.

## [1.0.1] - 2026-11-17

### Fixed
- Unpacked (developer-mode) extensions installed via "Load unpacked" are now detected: discovery follows the `path` field in each profile's `Preferences` file, in addition to `Extensions/settings`.
- `scanExtension` now accepts the documented `path` option to scan an arbitrary unpacked extension folder directly, without profile discovery (per PROTOCOL.md section 2).
- Improved error messages: "missing extensionId or path", and clear "not installed" vs "disabled in this profile" distinctions.

## [Unreleased]

### Added

- README: "How this compares to other tools" — an honest landscape map
  (CRXcavator-era cloud scanners, ExtAnalysis, source viewers, Chrome
  built-ins, antivirus companions) with a complements-not-competitors
  workflow and the niche this tool fills
- Animated README tour (`docs/screenshots/demo.gif`, 25 s): a scripted
  first-run story — onboarding, live scan, search, security findings,
  read-only source viewer, snapshot diff, compare matrix — recorded from the
  real dashboard and real scanner output via the demo harness. Reproducible
  with `node scripts/demo-gif.mjs` + `python3 scripts/make-gif.py`
  (Playwright + Pillow, dev-only).

## [1.0.0] — 2026-09-27

First public release.

### Added

- **Native scanner** (Go, stdlib-only, cross-compiles to Windows x64):
  - 16-action whitelisted JSON-RPC protocol over Chrome native messaging
    (full contract: `docs/PROTOCOL.md`)
  - 14 modular analyzers with an embedded, versioned rule engine
    (37 rules, 63 permission definitions, 23 API deprecations, 33 library
    signatures)
  - Token-level JavaScript lexer (strings, templates, regex, comments) —
    no `eval`, audited code is never executed
  - SHA-256 file hashing with incremental rescans and bounded concurrency;
    per-extension fault isolation
  - Secret detection (AWS / Google / Slack / GitHub / private keys / JWT /
    high-entropy) with redaction at the source
  - Archive hardening for `.zip` / `.crx` (CRX2/CRX3 headers, zip-bomb
    ratios, entry count, nesting depth, traversal & symlink rejection)
  - Snapshot store with scan history, before/after diffs and AI-answer cache
  - Optional LM Studio client (loopback only): model discovery, evidence-only
    prompts with injection delimiters, JSON schema validation, one retry,
    deterministic offline fallback
  - Exports: JSON, CSV, self-contained HTML (no CDN), local PDF
  - CLI modes for diagnostics, self-audit and fixture scanning
- **Chrome extension** (MV3, TypeScript + Vite):
  - First-run onboarding with live connectivity checks
  - Dashboard with KPIs, health summary, profile discovery
  - Extension inventory: search (name/id/domain/permission/finding), filter
    chips, seven sort orders — presentation only, never a ranking
  - 13-tab extension detail (overview, security, privacy, performance,
    permissions, host access, source, network, files, dependencies,
    compatibility, history, AI explanation)
  - Read-only source viewer: file tree, syntax highlighting, finding markers,
    jump-to-line, in-file search
  - Snapshot diff view (version/permission/host/domain/file/finding changes)
  - Side-by-side compare (documented differences, no winners) and
    cross-profile comparison
  - Review statuses, per-extension notes, locally-ignored findings
  - Ask-the-Auditor chat, LM Studio settings with test connection
  - Dark/light themes, keyboard navigation, ARIA labels
- **Installer**: per-user `Install.bat` / `Uninstall.bat` / `Diagnose.bat`
  (HKCU only, no elevation)
- **Tests**: 52 Go tests incl. protocol e2e over framed stdio, fixture-matrix
  scans, export format verification; local-only lint; self-audit
- **Docs**: README, PROTOCOL, SECURITY (threat model), PRIVACY, LIMITATIONS
- **Fixtures**: 14 deliberately misbehaving synthetic extensions
- **CI**: test + vet + cross-compile + extension build + lint + self-audit +
  package verification; release workflow publishing the Windows ZIP

### Security

- Extension ships with zero network permissions; scanner network traffic is
  loopback-only (LM Studio, optional)
- Two-tier path validation; `getSourceFile` bound to the scanned inventory
- Secrets redacted before leaving the scanner (UI, exports, AI prompts)

[1.0.0]: https://github.com/kimpearce888/chrome-extension-auditor/releases/tag/v1.0.0
