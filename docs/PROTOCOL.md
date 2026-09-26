# Native messaging protocol reference

The Chrome extension and the native scanner speak a strict, JSON-RPC-style
protocol over Chrome's native messaging transport. This document is the
complete, authoritative contract. If the code and this document disagree,
that is a bug — please report it.

## Transport

- Chrome native messaging: 4-byte little-endian length prefix + UTF-8 JSON, over the scanner's stdio.
- Host → extension messages are capped under Chrome's 1 MB limit; the scanner enforces ~900 KB and pages larger data through `getScan` / `getScanExtension`.
- The scanner never writes anything to stdout except protocol frames. Logs go to a file in the data directory.
- The scanner exits cleanly on stdin EOF (Chrome disconnected). Interrupted scans are marked and disclosed on next start.

## Envelope

```jsonc
// request (extension → scanner)
{ "requestId": "req-42-1695…", "action": "scanAll", "options": { … } }

// response (scanner → extension)
{ "requestId": "req-42-1695…", "success": true, "result": { … } }
// or
{ "requestId": "req-42-1695…", "success": false, "error": { "code": "ACCESS_DENIED", "message": "…" } }

// progress event (interleaved, same requestId, has "event")
{ "requestId": "req-42-1695…", "success": true, "event": "progress",
  "result": { "type": "progress", "stage": "scanning", "current": 3, "total": 11, "message": "Scanning abcdef…" } }
```

Requests missing `requestId` or `action`, malformed JSON, and **any action not
on the whitelist** are rejected. There is no generic execute/shell/read
action — by design.

## Action whitelist (16 actions)

| Action | Options | Result (summary) |
|---|---|---|
| `getStatus` | — | scanner/rules/analyzer versions, data dir, scan count, interrupted scans, local-only flag |
| `discoverProfiles` | — | Chrome profiles (`id`, `name`, `dir`, `available`, `error`) |
| `discoverExtensions` | `profiles?`, `managementInventory?` | extensions by ID with per-profile installations (path, enabled, version, install type, disable reasons) |
| `scanExtension` | `extensionId` or `path`, `mode`, LM options | full `ExtensionReport` |
| `scanAll` | `mode` (`quick`/`standard`/`deep`), `chromeVersion`, `managementInventory`, LM options | `ScanResult` (heavy fields trimmed; per-file detail via `getScanExtension`); emits `progress` events |
| `cancelScan` | — | `{ "cancelled": true }` — cooperative, checked between extensions |
| `getScan` | `scanId?` (defaults to last) | stored `ScanResult` |
| `getScanExtension` | `extensionId`, `scanId?` | one full `ExtensionReport` (paging-friendly) |
| `getSourceFile` | `extensionId`, `file`, `offset?` | `{ "content", "truncated" }` — read-only, only files inside the scanned package inventory, size-capped |
| `compareScans` | `scanA?`, `scanB?`, `extensionId?` | structured diff (defaults: two most recent scans) |
| `exportReport` | `format` (`json`/`csv`/`html`/`pdf`), `scope?`, `scanId?`, `path?` | `{ "path" }` — written to the scanner's reports directory (path-validated) |
| `deleteHistory` | `extensionId?`, `olderThanDays?`, `all?` | `{ "deleted" }` |
| `getLMStudioStatus` | LM options | `{ "reachable", "models" }` — loopback probe only |
| `testLMStudio` | LM options | connection test + model discovery |
| `askAuditor` | `extensionId`, `question`, LM options | AI answer grounded in collected evidence, or deterministic offline fallback |
| `scanArchive` | `path` | report for a user-selected `.zip`/`.crx` (hardened extraction) |

### LM options (shared by AI-related actions)

```jsonc
{
  "lmBaseUrl": "http://127.0.0.1:1234",  // only loopback accepted
  "lmModel": "",                         // empty = auto-discover first model
  "lmTemperature": 0.2,
  "lmMaxTokens": 1024,
  "lmTimeoutSec": 60
}
```

## Error codes

| Code | Meaning |
|---|---|
| `ACCESS_DENIED` | path validation failed (traversal, symlink escape, UNC, non-root target), unknown action, or missing required option |
| `SCAN_FAILED` | malformed request, scan error, internal error (recovered per-extension) |
| `PROFILE_UNAVAILABLE` | profile or package directory not readable |
| `ARCHIVE_TOO_LARGE` | archive limits exceeded (zip-bomb guard) |
| `FILE_CHANGED_DURING_SCAN` | package mutated while being read |
| `LM_STUDIO_UNAVAILABLE` | loopback endpoint not reachable (AI features fall back) |
| `AI_ANALYSIS_FAILED` | model output failed validation after retry (static fallback used) |

## Security properties

1. **Whitelist-only dispatch** — see the table above; nothing else exists.
2. **Two-tier path validation.** Paths supplied by the UI are validated
   strictly (must resolve inside the scanner's data root, no `..`, no
   symlinks, no UNC). Paths the scanner itself discovered from Chrome's
   preferences get a separate, deliberately bounded validation — Chrome
   may legitimately point at unpacked extensions outside the profile tree.
3. **`getSourceFile` is inventory-bound** — it only serves files recorded in
   a previous scan's file inventory for that extension, defeating traversal
   via the viewer.
4. **Response size guard** — oversized results are replaced with a paged
   pointer instead of being truncated mid-JSON.
5. **No secrets in evidence** — redaction happens before results leave the
   scanner, so the UI, exports and LM Studio prompts never see full values.

## Versioning

Every scan records `scannerVersion`, `ruleSetVersion` and `analyzerVersion`.
Rule sets are embedded, versioned JSON (`native/rules/*.json`); findings
carry the rule ID that produced them (e.g. `PERM-001`, `HOST-002`), so
historical results stay explainable as rules evolve.
