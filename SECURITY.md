# Security Policy

## Reporting a vulnerability

If you find a security issue in this project — especially anything that
breaks the local-only guarantee, escapes the read-only audit model, or
bypasses the native-host path validation — please report it privately:

1. Open a **security advisory**: GitHub → Security → "Report a vulnerability", or
2. Email the maintainer directly (see the repository owner profile).

Please do **not** open a public issue for vulnerabilities. We aim to respond
within a few days.

## Scope & guarantees

This project's security model is documented in detail in
[docs/SECURITY.md](docs/SECURITY.md). The short version of what we consider a
security bug:

- Any network egress to a non-loopback address from the scanner or the extension.
- Any way to make the scanner write outside its data directory, or modify the
  extensions it audits (the audit is read-only by contract).
- Native-host command execution beyond the 16 whitelisted actions.
- Path traversal / symlink escape through any action, including archive
  extraction and the source viewer.
- Secret values (API keys, tokens, private keys) appearing unredacted in the
  UI, exports, or LM Studio prompts.
- Prompt-injection from scanned source code causing the AI layer to produce
  instructions that the UI renders as trusted content.

## What is intentionally out of scope

- The auditor being unable to detect a specific novel obfuscation — that is a
  detection-gap issue (welcome as a regular issue/PR), not a vulnerability.
- Attacks requiring the user to run a malicious modified build of this tool.

## Hardening you can verify yourself

- `npm run lint` fails if the extension source or build output references any
  non-local URL.
- `npm run scan:self` runs the auditor on its own extension package.
- `Diagnose.bat` verifies the native-host registration and protocol loopback
  on your machine.
- Watch the scanner with any network monitor: loopback at most (LM Studio,
  optional).
