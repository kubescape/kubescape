---
kind: primary
routes:
  cli: CLI
steps:
  - text: The User validates the settings for Kubescape Cloud
    kind: actor
    actor: user
    entities: []
    contexts: { cli: { place: cli } }
  - text: The Product checks that the account ID, access key and both URLs are set and the URLs are valid
    kind: product
    actor: user
    entities:
      - { entity: cached-configuration, effect: reads, facts: [Account ID, Access key, Cloud API URL, Cloud report URL] }
    contexts: { cli: { place: cli } }
  - text: The Product reports the configuration valid
    kind: product
    actor: user
    entities: []
    contexts: { cli: { place: cli } }
---

# Validate for Kubescape Cloud

## Trigger

The User confirms Kubescape is ready to submit results.

## Outcome

The configuration is reported valid; passing checks are listed on request. For
offline use, only the URLs that are set are checked.
