---
appliesTo:
  - type: entity
    id: cached-configuration
    facts: [Access key]
references:
  - kind: code
    role: implementation
    target: core/cautils/config_output.go
---

# The access key is only ever shown masked

Viewing the configuration shows at most the last four characters of the access
key, and none of a key of eight characters or fewer.
