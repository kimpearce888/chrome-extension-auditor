# Contributing

Thanks for considering a contribution — and welcome. This project has a
strict product philosophy, and the contribution rules exist to protect it.

## The non-negotiables

1. **Evidence-first.** Every detection must report observed evidence
   (file, line, manifest field, pattern). Never infer intent, never label
   an extension "malicious", never invent a verdict.
2. **Calibrated wording.** `Potential…` and `Detected…` mean different
   things. Severity and confidence are separate axes. No scare tactics,
   no risk scores, no "87/100".
3. **Local-only.** No cloud calls, no telemetry, no remote resources, no
   new extension permissions unless strictly required — and never any
   non-loopback network code in the scanner. `npm run lint` enforces part
   of this; review enforces the rest.
4. **Read-only.** The auditor never modifies the extensions it audits.
5. **Honesty in tests.** Tests scan real fixture input and assert on real
   analyzer output. No hardcoded fake results, ever.

If your change violates any of these, open an issue first and let's talk
about it before you spend time on a PR.

## Development setup

```bash
git clone https://github.com/kimpearce888/chrome-extension-auditor.git
cd chrome-extension-auditor
npm install
npm run build     # build the extension
npm test          # go vet + Go test suite
npm run lint      # local-only resource lint
npm run demo      # dashboard against a synthetic profile (great for UI work)
```

The scanner is pure-Go with zero third-party modules; keep it that way
(the hermetic Windows cross-compile depends on it). The UI is TypeScript
with no runtime framework — small, explicit modules win over cleverness.

## Adding a detection rule

1. Rules live in versioned JSON under `native/rules/` plus the Go analyzers
   that emit them. Add the rule metadata (id, category, severity default,
   confidence default, why-it-matters, recommendation).
2. Add or extend a fixture under `fixtures/` that demonstrably triggers the
   rule — a test that scans the fixture and asserts the finding.
3. Make sure the wording is calibrated and the evidence carries location
   info (file/line).
4. Run the full gate: `npm test && npm run lint && npm run scan:self`.

## PR checklist

- [ ] `npm test` passes (Go vet + full suite)
- [ ] `npm run build` and `npm run lint` pass
- [ ] New detections have fixture-backed tests
- [ ] No secrets in fixtures (fake values only); output stays redacted
- [ ] Documentation updated (README / docs/PROTOCOL.md if the contract changed)

## Reporting detection gaps

Found an extension behavior the auditor should document but doesn't? Open a
feature-request issue with a minimal manifest/code snippet that should
trigger the new evidence. We treat detection gaps as backlog, not bugs.

## License

By contributing, you agree that your contributions are licensed under the
[MIT license](LICENSE).
