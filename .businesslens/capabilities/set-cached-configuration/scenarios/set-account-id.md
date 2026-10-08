---
kind: primary
routes:
  cli: CLI
steps:
  - text: The User sets the account ID
    kind: actor
    actor: user
    entities: []
    contexts: { cli: { place: cli } }
  - text: The Product saves the account ID in the Cached configuration, readable only by the User
    kind: product
    actor: user
    entities:
      - { entity: cached-configuration, effect: changes, facts: [Account ID] }
    contexts: { cli: { place: cli } }
---

# Set the account ID

## Trigger

The User connects Kubescape to a Kubescape Cloud account.

## Outcome

Later scans submit to that account while a report URL is configured.

## Edge cases

- The access key, API URL and report URL are set the same way.
