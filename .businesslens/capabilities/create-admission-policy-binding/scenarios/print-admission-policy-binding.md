---
kind: primary
routes:
  cli: CLI
steps:
  - text: The User names the binding and a library policy or control, with namespaces, labels and actions
    kind: actor
    actor: user
    entities:
      - { entity: control, effect: reads, facts: [Control ID] }
    contexts: { cli: { place: cli } }
  - text: The Product prints the Admission policy binding, denying violations unless another action was chosen
    kind: product
    actor: user
    entities:
      - { entity: admission-policy-binding, effect: creates, facts: [Name, Policy, Actions, Namespaces, Labels] }
    contexts: { cli: { place: cli } }
---

# Create a binding

## Trigger

The User wants the cluster to enforce one Kubescape admission policy.

## Outcome

The binding manifest is printed or written to a file, for the User to apply.

## Edge cases

- Deny and Warn cannot be chosen together, and an action cannot be repeated.
- Namespaces are refused when every resource the policy covers is cluster-scoped.
- Labels are matched only by equality; conflicting values are refused.
