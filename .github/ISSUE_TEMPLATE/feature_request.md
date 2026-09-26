name: Feature request
description: Suggest a new analyzer, rule, or product capability
labels: ['enhancement']
body:
  - type: textarea
    id: problem
    attributes:
      label: What evidence gap or problem should this solve?
      description: The auditor is evidence-first — describe what you want to *observe*, not just what you want built.
    validations:
      required: true
  - type: textarea
    id: proposal
    attributes:
      label: Proposed behavior
      description: What should the scanner detect or the UI show? Ideally include an example manifest/code snippet that should trigger it.
  - type: dropdown
    id: area
    attributes:
      label: Area
      options:
        - New detection rule / analyzer
        - Snapshot diffing
        - Dashboard UI
        - Exports
        - LM Studio / AI explanations
        - Installer / packaging
        - Documentation
