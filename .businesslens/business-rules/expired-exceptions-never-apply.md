---
appliesTo:
  - type: entity
    id: exception
    facts: [Expiry]
references:
  - kind: code
    role: implementation
    target: core/pkg/opaprocessor/processorhandlerutils.go#filterExpiredExceptions
---

# An expired exception never suppresses a finding

An exception past its expiry is ignored, and an exception audit reports it as
expired.
