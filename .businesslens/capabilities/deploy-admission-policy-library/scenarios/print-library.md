---
kind: primary
routes:
  cli: CLI
steps:
  - text: The User asks to deploy the library
    kind: actor
    actor: user
    entities: []
    contexts: { cli: { place: cli } }
  - text: The Product prints the library built into this release, ready to apply
    kind: product
    actor: user
    entities: []
    contexts: { cli: { place: cli } }
---

# Print the built-in library

## Trigger

The User prepares a cluster for Kubescape admission policies.

## Outcome

The manifests are printed for the User to apply, for example by piping them to
`kubectl apply`.
