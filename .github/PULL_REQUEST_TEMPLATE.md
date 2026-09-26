## Summary

<!-- What does this PR change and why? -->

## Type of change

- [ ] Bug fix (no behavior change in reported findings)
- [ ] New detection rule / analyzer capability
- [ ] Dashboard UI change
- [ ] Installer / packaging
- [ ] Documentation
- [ ] Other

## Evidence-first checklist

Detection rules and analyzers MUST stay evidence-based. If this PR adds or
changes a rule, please confirm:

- [ ] The finding reports *observed evidence* (file, line, manifest field) — not inferred intent.
- [ ] Severity and confidence are calibrated (`Potential…` vs `Detected…` wording).
- [ ] No dynamic code execution, no network calls beyond 127.0.0.1, no new permissions unless strictly required.
- [ ] Secrets in new test fixtures are fake; real-looking values are redacted in output.
- [ ] `npm test`, `npm run lint` and (for scanner changes) `go test ./...` pass.

## Testing

<!-- How did you verify the change? Which fixtures/cases cover it? -->
