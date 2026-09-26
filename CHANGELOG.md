# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project
adheres to [Semantic Versioning](https://semver.org/).

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
