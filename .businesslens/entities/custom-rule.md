---
domain: policy
relations:
  - entity: rule-test-case
    verb: has
    cardinality: one-to-many
references:
  - kind: code
    role: implementation
    target: core/pkg/policytest/scaffold.go#Scaffold
  - kind: code
    role: implementation
    target: core/cautils/getter/customrules.go#LoadCustomRules
---

# Custom rule

A Rego security rule a User writes and keeps in a directory of its own, with its
test cases beside it, and supplies to scans alongside the downloaded frameworks.

## Information kept

- **Name** — the rule's name, taken from its directory
- **Rule source** — the Rego that decides which resources fail
- **Matched kinds** — the resource kinds the rule is evaluated against
- **Base score** — the 1 to 10 score its severity is derived from
- **Description** — what the rule checks
- **Remediation** — how to fix a resource that fails it
