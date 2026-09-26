# LIMITATIONS — Local Chrome Extension Auditor

This tool is deliberately honest about what static, local analysis can and cannot know (§117). Read this before acting on any finding.

## What it CAN know

- installed extension metadata (from Chrome's own preference stores and the management API)
- requested permissions and host patterns (from manifests)
- package contents: files, sizes, hashes
- statically visible source patterns (API usage, timers, observers, network literals, injection sinks, …)
- referenced URLs/domains and their likely classification
- many static indicators of performance, compatibility and code health

## What it CANNOT prove

- **Malicious intent.** No static tool can prove intent. Obfuscation, broad permissions and analytics endpoints each have legitimate uses. The wording of every finding reflects this.
- **Exact real-world CPU or RAM consumption per extension.** Chrome does not expose reliable per-extension resource attribution to other extensions. The auditor reports *static resource-risk patterns* with confidence levels instead, and says so explicitly (§43). It never fabricates numbers.
- **Undiscovered vulnerabilities or zero-days.**
- **Server-side behavior.** What a remote endpoint actually does with data is invisible to a local scan.
- **Behavior hidden behind remote configuration** (features enabled server-side after review).
- **Behavior that only occurs at runtime** under conditions static analysis cannot reproduce (dynamically generated code, user-triggered flows).

## Static analysis boundaries

- **JavaScript analysis is token-level, not full AST.** A custom lexer recognizes strings, template literals, regex literals and comments so patterns inside them are not misreported — but it is not a complete parser. Dynamic dispatch (`obj[name]()`), computed member chains and framework-generated indirection can hide usage. This is why unused-permission findings say "potentially unused" and carry medium confidence.
- **Minified and bundled code** is harder to reason about. Readability findings quantify this instead of pretending certainty.
- **Obfuscation detection is heuristic** (entropy, base64 blobs, hex identifiers, escape density). It reports "difficult to analyze / manual review recommended" — never "malicious".
- **Dependency identification** relies on a local signature database and reports confidence levels; unknown or renamed libraries are invisible to it.

## Runtime attribution

The optional Windows process observation (§44) is deliberately conservative: browser-wide CPU/RAM is never attributed to a single extension because that attribution is not technically defensible. Where direct per-extension measurement is unavailable, the UI states this.

## Chrome version differences

- Manifest V2 detection reflects Chrome's phase-out; exact enforcement dates vary by release channel and enterprise policy.
- Deprecated-API knowledge comes from a versioned local rule set (`native/rules/apideprecations.json`). It may lag behind the newest Chrome releases.
- The scanner reads Chrome's profile `Preferences`/`Secure Preferences` files. Internal formats can change between Chrome versions; the scanner degrades to honest "Not available" values rather than guessing.

## Managed / enterprise Chrome

- Policy-installed extensions are flagged as such when discoverable.
- On managed Chrome, silent extension installation is controlled by enterprise policy. The installer detects the restriction and offers the supported path instead of bypassing it (§132).
- Some enterprises store profiles in non-standard locations; the scanner covers the standard ones and any user-configured override.

## Packed code

- CRX/ZIP analysis works on the package as provided; contents not included in the archive (fetched at runtime) are obviously not analyzed.
- Source maps, when present, improve readability analysis; their absence lowers audit confidence but is not itself a problem (minification is normal practice — §36).
