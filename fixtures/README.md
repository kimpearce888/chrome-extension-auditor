# Test fixtures

These 14 synthetic extensions are the scanner's test matrix. They are
**deliberately misbehaving on purpose** so every analyzer has something real
to find. They are never loaded into a browser; they exist to be scanned.

> **No fixture contains a real secret.** Anything that looks like an API key
> or token is a fake value chosen to match detection patterns. The scanner
> redacts them in output anyway — that behavior is itself under test.

| Fixture | What it demonstrates |
|---|---|
| `01-simple` | Well-behaved baseline; expects a near-clean audit |
| `02-large` | Many files / large bundles; performance & coverage limits |
| `03-minified` | Minified-but-not-obfuscated code (the two are distinguished) |
| `04-content-heavy` | Content scripts on broad match patterns, all frames, document_start |
| `05-permission-heavy` | Broad permissions incl. high-privilege APIs; permission-usage correlation |
| `06-network-heavy` | fetch/XHR/WebSocket/beacon endpoints across classified destinations |
| `07-timer-heavy` | Aggressive timers/setInterval usage in a service worker |
| `08-observer-heavy` | MutationObservers with broad configs |
| `09-native-messaging` | `nativeMessaging` permission + `connectNative` usage |
| `10-malformed-manifest` | Broken `manifest.json` (must fail gracefully, not crash) |
| `11-missing-files` | Manifest references files that don't exist |
| `12-obfuscated` | Obfuscation indicators (hex strings, `String.fromCharCode`, `_0x` names) |
| `13-large-package` | Oversized package contents |
| `14-legacy-mv2` | Manifest V2 with deprecated APIs (`browser_action`, `chrome.tabs.executeScript`) |

The Go test suite scans these fixtures and asserts that the expected rule
IDs fire (e.g. `14-legacy-mv2` must produce `COMPAT-001/002/003`). If you
add a detection rule, add or extend a fixture here and a test that scans it.
