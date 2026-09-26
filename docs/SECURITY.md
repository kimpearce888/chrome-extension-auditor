# SECURITY — Local Chrome Extension Auditor

## Principles

1. **Read-only by default (§105).** The auditor never disables, uninstalls, patches or modifies another extension. The only writes it performs are to its own data directory.
2. **Scanned code is untrusted data (§53).** It is never imported, evaluated, loaded as a webpage, or executed. Analysis is static.
3. **Local-only networking (§101).** The only network endpoint the product ever contacts is the user-configured LM Studio server (default `http://127.0.0.1:1234`).

## Native host restrictions (§102, §156)

The native host is the privileged component. The Chrome extension cannot make it:

- execute shell commands or PowerShell
- launch arbitrary programs
- delete or modify arbitrary files
- touch the registry beyond its own HKCU native-messaging key (written by the installer, not by the host)

The host accepts **only** these whitelisted actions over a JSON-RPC-style protocol (`requestId`, `action`, `options` / `success`, `result|error`):

`getStatus`, `discoverProfiles`, `discoverExtensions`, `scanExtension`, `scanAll`, `cancelScan`, `getScan`, `getScanExtension`, `getSourceFile`, `compareScans`, `exportReport`, `deleteHistory`, `getLMStudioStatus`, `testLMStudio`, `askAuditor`, `scanArchive`

There is no generic `execute`, `shell`, `command`, `run` or `powershell` action — unknown actions are rejected with `ACCESS_DENIED`.

The additions beyond the base nine (§156) are documented, narrowly scoped read/analysis operations needed for the UI (paged report fetch under the 1 MB native-messaging limit, the read-only source viewer, cancellation, LM Studio status/tests, per-extension AI questions, and user-selected archive analysis).

## Path validation (§103)

Every filesystem path received or derived is validated:

- empty, relative and `..`-containing paths rejected
- UNC paths (`\\server\share`) rejected
- scanning restricted to discovered Chrome profile locations, the app's own temp dirs, and (for `scanArchive`) an explicitly user-provided archive path
- symlink escapes are detected by walking path components and resolving symlinks against the allowed roots
- `getSourceFile` only serves files that are part of the previously scanned inventory

## Archive safety (§54, §104)

CRX/ZIP extraction (for the optional archive analysis flow) protects against:

- path traversal, absolute paths, drive letters in entry names
- symlinks inside archives
- zip bombs: per-entry and total uncompressed caps (512 MB default), compression-ratio check (100:1), entry-count cap (20,000)
- nested archives: depth limited to 2
- extraction always happens into a unique temp directory, never over an existing extension directory; temp dirs are removed after analysis

## File limits (§55)

Per-file analysis cap (2 MB text), per-package file-count cap (10,000), package-size cap (1 GB). When limits are hit, the scan records partial coverage and says so — one malformed or oversized extension can never freeze the scanner, and the report explains exactly what was skipped.

## Secret redaction (§39, §173)

Conservative patterns (AWS keys, GitHub tokens, JWTs, private-key blocks, password-like assignments, …) are detected in scanned code. **Values are never displayed, exported, or sent to LM Studio.** Findings contain only the file, line and category, plus a short hash for deduplication. Excerpts destined for AI input pass through the same redaction.

## Local-only AI (§172, §152)

- Scanned material is delimited as `BEGIN SCANNED EVIDENCE … END SCANNED EVIDENCE` and instructed to be treated as data, never instructions (prompt-injection defense).
- The model may only explain the scanner's evidence. It cannot introduce findings, permissions or domains the deterministic scanner did not observe — the scanner is authoritative.
- Responses are validated JSON; malformed responses get one repair retry, then a deterministic fallback. The app never crashes on AI failures.

## Store integrity (§159)

- atomic writes (temp file + rename) with a rolling `.bak`
- schema versioning and migration hooks
- corruption is detected and quarantined, not propagated
- no secrets, no full source files are persisted

## Self-audit (§138, §101, §139, §140)

`scanner.exe --self-audit <path>` (wired to `npm run scan:self` in development) re-analyzes the auditor's own built extension: every URL reference must be localhost/none, no `fetch`/`XMLHttpRequest`/`WebSocket`/`sendBeacon` may exist in the runtime output, and telemetry/analytics keywords are surfaced for review. The package build (§ package) fails if any of these checks fail.

## Reporting bugs

Security issues in the auditor itself are best reported privately to the package maintainer. Please include the Diagnose.bat output and scanner version.
