# Local Chrome Extension Auditor

A **fully local** security, privacy, performance, compatibility and code-health auditor for the Chrome extensions installed on your computer.

- No cloud. No SaaS. No telemetry. No account.
- The AI component (optional) runs in **your own LM Studio** on `http://127.0.0.1:1234`.
- Everything keeps working with the internet completely unplugged.
- The auditor is **read-only**: it never disables, modifies, patches or uninstalls another extension.

---

## What this tool does

It inspects every Chrome extension installed in every Chrome profile on the machine and produces an evidence-based audit covering:

- security risks, excessive or suspicious permissions, broad host access
- privacy exposure (browsing data access, cookies, analytics endpoints)
- potential performance patterns (timers, MutationObservers, polling, heavy content scripts)
- compatibility problems (Manifest V2, deprecated APIs, obsolete fields)
- package health (size, duplicate dependencies, minification, obfuscation indicators)
- network destinations referenced by the code, classified (CDN, analytics, …)
- changes between scans (new permissions, new domains, code changes)
- readability of the source and what that means for audit confidence

**What it deliberately is not**: an antivirus, a malware scanner, or a guarantee that anything is safe. It documents observed evidence with severity and confidence ratings, and you make the decisions. See `LIMITATIONS.md`.

## Architecture

```
Chrome
  |
  v
Auditor extension (MV3 UI: dashboard, source viewer, ask-the-auditor)
  |  native messaging (strict JSON-RPC-style, whitelisted actions)
  v
Local scanner (Go, standalone scanner.exe, Windows x64)
  |  reads
  v
Chrome profiles + extension package files
  |
  v
Local store (scan history, snapshots, findings)
  |
  v
Optional: LM Studio (http://127.0.0.1:1234) for local AI interpretation
```

The extension itself has **no host permissions** and performs **zero network calls**. All filesystem analysis happens in the native scanner; all AI calls go to your local LM Studio endpoint.

## Installation

Requirements: Windows 10/11 x64, Google Chrome.

1. Extract the ZIP to a folder you control (e.g. `C:\Tools\Local-Extension-Auditor`).
2. Run `Install.bat`.
3. When asked, open `chrome://extensions`, enable **Developer mode**, click **Load unpacked**, and select the `extension` folder inside the extracted package. (Chrome does not allow silent installation of self-hosted extensions outside enterprise policy — the installer will never try to bypass that.)
4. Open the auditor from the toolbar icon (Alt+Shift+A) and run your first scan.

The install is per-user (HKCU registry only, no elevation): it registers the native messaging host `com.local.extensionauditor.scanner` pointing at `native\scanner.exe` inside the extracted folder.

## LM Studio setup (optional)

1. Install LM Studio from lmstudio.ai and start its local server (default `http://127.0.0.1:1234`).
2. Download any chat model you like.
3. In the auditor: Settings → LM Studio → **Test Connection** → pick your model.

Without LM Studio the complete technical audit still works — you just don't get AI explanations (deep-scan interpretation and "Ask the Auditor").

## Scanning modes

| Mode | What it does |
|---|---|
| Quick | inventory + manifest + permissions |
| Standard | + source scan, network inventory, performance heuristics, dependency detection |
| Deep | + AI interpretation via LM Studio, snapshot comparison |

Every scan records scanner / rule-set / analyzer versions so changes between audits stay explainable.

## What the findings mean

Every finding carries **severity** (critical/high/medium/low/informational), **confidence** (high/medium/low) and **evidence** (file, line, manifest field, pattern). Severity is never inflated just because a permission sounds scary. "Potential" and "Detected" mean different things — the wording is deliberate. You can mark findings as reviewed, ignore them locally (evidence is kept), and take notes per extension.

## Known limitations

Static analysis cannot prove intent, measure real per-extension CPU/RAM in every situation, see server-side behavior, or analyze code generated at runtime. Full details in `LIMITATIONS.md`.

## Troubleshooting

- **"Native scanner not connected"** — run `Install.bat` again, then reload the extension in `chrome://extensions`. Check `Diagnose.bat` for a PASS/FAIL checklist.
- **Scan shows 0 extensions** — Chrome must have at least one profile with a `Preferences` file; run Chrome once, then scan again.
- **AI explanations missing** — LM Studio server not running, or no model loaded. Static audit is unaffected.
- **A specific extension shows low coverage** — its files exceeded the configured safety limits (size/count). The coverage note explains exactly what was skipped.

## Security

Read `SECURITY.md` for the native-host threat model, command whitelist, path validation, archive hardening and secret redaction. Run `Diagnose.bat` any time to verify your installation, and `npm run scan:self` (development) to audit the auditor itself.

## Development

```
npm install
npm run build            # vite + typescript build of the extension
npm run test             # go test (scanner) + vet
npm run lint             # local-only network audit of source & dist
npm run scan:self        # scanner --self-audit against the built extension
npm run package          # build + cross-compile scanner.exe + assemble ZIP
npm run package:windows  # same, producing Local-Chrome-Extension-Auditor-Windows.zip
```

The Go scanner builds with the standard toolchain only (zero third-party modules), which keeps the Windows cross-compile hermetic: `go build -o scanner.exe .`

## Packaging

`npm run package` produces `Local-Chrome-Extension-Auditor-Windows.zip` containing exactly the distribution layout (no node_modules, no build temporaries). The final package runs without Node.js, Go, or any cloud service.
