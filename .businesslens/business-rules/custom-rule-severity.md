---
appliesTo:
  - type: entity
    id: custom-rule
    facts: [Base score]
references:
  - kind: doc
    role: intent
    target: docs/cli-reference.md
  - kind: code
    role: implementation
    target: core/cautils/getter/customrules.go
---

# A custom rule's severity follows its base score

A custom rule is medium severity unless it declares a base score from 1 to 10,
bucketed as low (1–3), medium (4–6), high (7–8) and critical (9–10); a
malformed, out-of-range or repeated base score fails the scan.
