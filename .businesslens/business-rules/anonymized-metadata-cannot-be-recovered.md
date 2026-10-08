---
appliesTo:
  - type: entity
    id: scan-report
    effect: creates
    to: Anonymized
references:
  - kind: doc
    role: intent
    target: docs/cli-reference.md
---

# Anonymized metadata cannot be recovered

Pseudonyms written when hiding metadata cannot be reversed by decryption, and
identical values yield identical pseudonyms across reports.

## Rationale

Pseudonyms come from an unsalted hash, so values from small or guessable sets
can be matched by hashing candidates; anonymizing reduces incidental exposure
but is not confidentiality.
