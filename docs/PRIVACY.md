# PRIVACY — Local Chrome Extension Auditor

This page states what the product does with your data. Every claim below matches the implementation; see SECURITY.md for how each guarantee is enforced.

## The short version

**Nothing leaves your computer. Ever.**

- No cloud AI. All interpretation (when enabled) runs in your own LM Studio on `http://127.0.0.1:1234`.
- No telemetry, no analytics, no crash reporting, no tracking pixels, no remote error reporting.
- No user account, no login, no cloud synchronization.
- No remote database — scan history lives in a local store under `%LOCALAPPDATA%\LocalExtensionAuditor`.
- Extension files are analyzed locally by the native scanner on your own disk.
- Reports are generated locally and exported to your local reports folder.
- Secret-like values detected in scanned extensions are **redacted before any AI processing** and never displayed.

## What is stored locally

| Data | Where | Deletable |
|---|---|---|
| Scan history, findings, snapshots | `%LOCALAPPDATA%\LocalExtensionAuditor\store.json` | Settings → Delete all audit history |
| File hashes + per-file analysis caches | same store | same |
| AI summaries (cached with model + prompt version) | same store | same |
| Your notes and review statuses | extension storage | with the extension's own data |
| Exported reports | `%LOCALAPPDATA%\LocalExtensionAuditor\reports` | delete files manually |

The store never contains complete source files of scanned extensions — hashes, findings and references only.

## What the auditor can access

- The auditor **extension** requests only: `management` (enumerate installed extensions), `nativeMessaging` (talk to the scanner), `storage` (your settings), `alarms` (optional scheduled scans). It has **no host permissions**, so it cannot read any website.
- The **native scanner** reads Chrome profile preferences and extension package directories. It never writes to them. It never executes scanned code. It cannot and does not send anything anywhere.

## Verifying the claims yourself

- The built extension contains zero network APIs and zero non-local URLs — enforced by `scripts/lint.mjs` on every package build, and checkable by anyone with a text editor.
- The scanner source ships in the repository; `npm run scan:self` runs the auditor's own analysis over itself.
- `Diagnose.bat` shows exactly which local components are active and reachable.

## LM Studio specifics

When you enable AI features, the scanner sends a **curated evidence summary** (permissions, host patterns, findings, network hosts, package stats — never raw source dumps) to your local LM Studio endpoint. Secrets are redacted before sending. If LM Studio is unavailable, the deterministic audit continues unaffected.
