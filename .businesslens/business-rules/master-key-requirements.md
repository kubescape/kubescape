---
appliesTo:
  - type: capability
    id: scan-misconfigurations
  - type: capability
    id: decrypt-scan-report
references:
  - kind: code
    role: implementation
    target: core/pkg/reportcrypto/masterkey.go#ValidateMasterKey
  - kind: code
    role: implementation
    target: core/pkg/reportcrypto/masterkey.go#GetMasterKeyFromEnv
---

# Encryption needs exactly one master key of at least 16 bytes

Encrypting and decrypting report metadata need exactly one master key, given
either as a passphrase or as hexadecimal, of at least 16 bytes.
