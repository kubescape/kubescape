---
kind: primary
routes:
  cli: CLI
steps:
  - text: The User deletes the cached settings
    kind: actor
    actor: user
    entities: []
    contexts: { cli: { place: cli } }
  - text: The Product removes the cached file, clearing every setting
    kind: product
    actor: user
    entities:
      - { entity: cached-configuration, effect: changes, facts: [Account ID, Access key, Cloud API URL, Cloud report URL] }
    contexts: { cli: { place: cli } }
---

# Delete every setting

## Trigger

The User disconnects Kubescape from Kubescape Cloud on this machine.

## Outcome

No cached settings remain; settings from the cluster or the environment still
apply.
