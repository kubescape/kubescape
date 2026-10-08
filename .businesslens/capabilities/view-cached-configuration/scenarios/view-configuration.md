---
kind: primary
routes:
  cli: CLI
steps:
  - text: The User asks to view the settings, optionally one key
    kind: actor
    actor: user
    entities: []
    contexts: { cli: { place: cli::cached-configuration } }
  - text: The Product merges the cached file, the cluster's configuration and credentials, and the environment
    kind: product
    actor: user
    entities:
      - { entity: cached-configuration, effect: reads, facts: [Account ID, Access key, Cloud API URL, Cloud report URL] }
    contexts: { cli: { place: cli::cached-configuration } }
  - text: The User reads the settings in effect, with the access key masked
    kind: actor
    actor: user
    entities:
      - { entity: cached-configuration, effect: reads, facts: [Account ID, Access key, Cloud API URL, Cloud report URL] }
    contexts: { cli: { place: cli::cached-configuration } }
---

# View the settings in effect

## Trigger

The User checks which account and URLs Kubescape will use.

## Outcome

The User sees the settings as text, JSON or YAML; a key that is unknown or not
set is an error.
