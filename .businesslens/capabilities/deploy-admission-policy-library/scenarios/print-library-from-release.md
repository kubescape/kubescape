---
kind: alternative
routes:
  cli: CLI
steps:
  - text: The User asks to deploy the library of a named release
    kind: actor
    actor: user
    entities: []
    contexts: { cli: { place: cli } }
  - text: The Product downloads that release's library and prints it, ready to apply
    kind: product
    actor: user
    entities: []
    contexts: { cli: { place: cli } }
---

# Print a released library

## Trigger

The User needs a library version other than the built-in one.

## Outcome

The named release's manifests are printed; an invalid release tag or a download
that does not finish in time fails the command.
