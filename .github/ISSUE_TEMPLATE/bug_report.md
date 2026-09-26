name: Bug report
description: Something does not work as documented
labels: ['bug']
body:
  - type: markdown
    attributes:
      value: |
        Thanks for taking the time to report a bug. Please include enough
        evidence (screenshots, exported reports, Diagnose.bat output) for us
        to reproduce it. Remember: never paste real secrets — the auditor
        redacts them, and so should you.
  - type: textarea
    id: what-happened
    attributes:
      label: What happened?
      description: A clear description of the bug, plus what you expected instead.
    validations:
      required: true
  - type: dropdown
    id: component
    attributes:
      label: Component
      options:
        - Native scanner (Go)
        - Dashboard UI (extension)
        - Installer / Uninstaller / Diagnostics
        - Exports (JSON / CSV / HTML / PDF)
        - LM Studio integration
        - Documentation
        - Other
    validations:
      required: true
  - type: input
    id: version
    attributes:
      label: Auditor version
      description: Shown in Settings, or run `scanner.exe --version`
      placeholder: '1.0.0 (rules 1.0.0)'
  - type: textarea
    id: logs
    attributes:
      label: Evidence (Diagnose.bat output / exported report / console output)
      description: Paste relevant output. Redact anything sensitive.
      render: shell
