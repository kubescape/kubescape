# Image VEX Output

Kubescape image scans can attach VEX status data to vulnerabilities. When a
scan result includes VEX data, human-readable image vulnerability tables include
two extra columns:

- `VEX Status`
- `VEX Justification`

Example:

| Severity | Vulnerability | KEV | EPSS | Component | Version | Fixed in | Image | VEX Status | VEX Justification |
|---|---|---|---|---|---|---|---|---|---|
| High | CVE-2026-0001 |  | 0.2% (41st) | openssl | 1.0.0 |  | nginx:latest | not_affected | component_not_present |

When no vulnerability has VEX data, the two VEX columns are omitted.
