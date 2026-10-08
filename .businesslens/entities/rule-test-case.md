---
domain: policy
references:
  - kind: code
    role: implementation
    target: cmd/policy/test.go
  - kind: code
    role: implementation
    target: core/pkg/policytest/scaffold.go#Scaffold
---

# Rule test case

One test case of a custom rule, kept in a directory of its own beside the rule:
input resources and the results the rule is expected to produce for them.

## Information kept

- **Name** — the case's name, taken from its directory
- **Input** — the resources the rule is evaluated against, with any control configuration it needs
- **Expected result** — the results the rule is expected to produce for that input
