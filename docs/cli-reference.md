# Kubescape CLI Reference

This document provides a complete reference for all Kubescape CLI commands and options.

## Global Options

These options are available for all commands:

| Option | Description |
|--------|-------------|
| `--cache-dir <path>` | Cache directory (default: `~/.kubescape`) |
| `--kube-context <context>` | Kubernetes context to use (default: current-context) |
| `-l, --logger <level>` | Log level: `debug`, `info`, `warning`, `error`, `fatal` |
| `--server <url>` | Backend discovery server URL |
| `-h, --help` | Help for any command |

---

## kubescape scan

Scan Kubernetes clusters, files, or images for security issues.

### Synopsis

```bash
kubescape scan [target] [flags]
```

### Target Types

- No target: Scans the current cluster
- Path: Scans local YAML files, Helm charts, or Kustomize directories
- URL: Scans a Git repository

### Flags

| Flag | Description | Default |
|------|-------------|---------|
| `--account <id>` | Kubescape SaaS account ID | from cache |
| `--access-key <key>` | Kubescape SaaS access key | from cache |
| `--compliance-threshold <float>` | Fail if compliance score is below threshold. Applies to `scan framework`, `scan control`, and `--view resource\|control` — see [score thresholds](#score-thresholds). | `0` |
| `--controls-config <path>` | Path to controls configuration file | - |
| `--custom-rules <path>` | Path to user-authored custom rules — see [custom rules](#custom-rules) | - |
| `-e, --exclude-namespaces <ns>` | Namespaces to exclude (comma-separated) | - |
| `--encrypt` | Encrypt sensitive report metadata using the master key provided through the `KUBESCAPE_MASTER_KEY` environment variable. Requires `--format json` for reports that will later be decrypted with `kubescape decrypt`. If both `--encrypt` and `--hide` are specified, `--encrypt` takes precedence. | `false` |
| `--exceptions <path>` | Path to exceptions file | - |
| `--audit-exceptions` | Include exception usage details in supported scan outputs | `false` |
| `--fail-coverage-below <float>` | Fail if the scan coverage score is below threshold (`0` disables). Applies in every view — see [score thresholds](#score-thresholds). | `0` |
| `-f, --format <format>` | Output format: `pretty-printer`, `json`, `junit`, `prometheus`, `pdf`, `html`, `sarif`, `gitlab-sast`, `yaml`, `csv` | `pretty-printer` |
| `--hide` | Replace sensitive report metadata with deterministic pseudonyms. Ignored when `--encrypt` is also specified. | `false` |
| `--host-scan` | Enable host data collection from cluster nodes for certain controls. When not set, Kubescape auto-detects node-agent CRDs and uses a CRD-based host sensor if available. Use `--host-scan=false` to disable host data collection. See the [Kubescape operator](https://github.com/kubescape/helm-charts/tree/main/charts/kubescape-operator) for a managed alternative. | auto-detect |
| `--include-namespaces <ns>` | Namespaces to include (comma-separated) | - |
| `--label-selector <selector>` | Filter collected resources by Kubernetes label selector. Accepts any expression `kubectl -l` supports, e.g. `app=nginx,env!=dev` or `env in (prod,staging)`. Syntax is validated before scanning begins; filtering is applied during live cluster collection and ignored when scanning local files. | - |
| `--keep-local` | Don't report results to backend | `false` |
| `--notify <url>` | POST the posture scan summary to a webhook URL. Slack incoming webhooks receive Block Kit; other destinations receive generic JSON. Repeat for multiple endpoints. Delivery is best-effort and does not affect scan exit status. Not supported by `scan image`. | - |
| `--kubeconfig <path>` | Path to kubeconfig file | - |
| `-o, --output <path>` | Output file path | stdout |
| `--otel-endpoint <endpoint>` | Export scan traces and metrics to an OTLP collector — see [OpenTelemetry export](#opentelemetry-export). Accepts `host:port` (plaintext) or a `http(s)://` URL. | `OTEL_EXPORTER_OTLP_ENDPOINT` |
| `--scan-images` | Also scan container images for vulnerabilities | `false` |
| `--image-platform <platform>` | OCI platform for workload image scans, such as `linux/amd64`. Overrides platform inferred from Nodes and hard scheduling constraints | inferred |
| `--severity-threshold <sev>` | Fail if findings at or above severity: `low`, `medium`, `high`, `critical`. Failed controls with unknown severity (missing base score) are treated as exceeding any threshold | - |
| `--skip-db-update` | Do not update the vulnerability database before scanning images; uses the locally cached database. Fails if the local database is missing or unusable (run once without this flag to download it). | `false` |
| `--submit` | Submit results to Kubescape SaaS | `false` |
| `--use-artifacts-from <path>` | Load artifacts from local directory (offline mode) | - |
| `--use-from <path>` | Load specific policy from path | - |
| `-v, --verbose` | Display all resources, not just failed ones | `false` |
| `--view <type>` | View type: `security`, `control`, `resource` | `security` |

### Webhook notifications

Use `--notify` to send a compact summary after a posture scan. Official Slack and GovSlack incoming webhook URLs receive a Block Kit message; every other URL receives the existing JSON `summaryDetails` object:

```bash
export SLACK_WEBHOOK_URL='https://hooks.slack.com/services/T00000000/B00000000/SECRET'
kubescape scan manifests/ --notify "$SLACK_WEBHOOK_URL"
kubescape scan manifests/ --notify https://hooks.example.com/kubescape
kubescape scan manifests/ --notify https://ops.example.com/kubescape --notify https://audit.example.com/kubescape
```

Each destination gets one synchronous request with `Content-Type: application/json`; Kubescape allows up to five seconds per destination and does not follow redirects. Failures are logged as warnings and never override the scan's own exit status. The payload follows `--min-severity` and `--max-severity` output filtering. `--severity-threshold` continues to affect only the exit status.

Slack messages contain the compliance score, passed/failed/skipped control counts, and up to ten failing controls ordered by severity, failed resource count, and control ID. The top-level `text` field provides a notification and accessibility fallback. For example:

```json
{
  "text": "Kubescape scan completed: 73.2% compliance; 2 of 8 controls failed.",
  "blocks": [
    {"type": "header", "text": {"type": "plain_text", "text": "Kubescape scan results"}},
    {"type": "section", "fields": [
      {"type": "mrkdwn", "text": "*Controls*\n2 failed / 8 total\n5 passed · 1 skipped"},
      {"type": "mrkdwn", "text": "*Compliance score*\n73.2%"}
    ]},
    {"type": "section", "text": {"type": "mrkdwn", "text": "*Top failing controls*\n• *Critical* · `C-0001` — Privileged container"}}
  ]
}
```

Generic destinations continue to receive only the scan summary. An abridged example is:

```json
{
  "status": "failed",
  "frameworks": [],
  "ResourceCounters": {"passedResources": 5, "failedResources": 2, "skippedResources": 1, "excludedResources": 0},
  "score": 73.2,
  "complianceScore": 73.2
}
```

The summary and Slack control names may contain identifiers from the scan. Use `--hide` where appropriate and send only to trusted webhook endpoints. A Slack webhook URL is itself a secret; keep it out of source control and prefer passing it through an environment variable. Microsoft Teams Adaptive Card formatting is not currently included.

### Custom rules

`--custom-rules` loads user-authored rules alongside the downloaded framework.
Two on-disk layouts are accepted, and they can be mixed in one directory.

A **rule directory** holds `raw.rego` next to `rule.metadata.json`. This is the
layout of this repository's `rules/` tree and the one `kubescape policy test`
reads, so a rule can be tested and then scanned without being reshaped:

```
myrules/
  no-privileged-containers/
    raw.rego
    rule.metadata.json
  no-host-network/
    raw.rego
    rule.metadata.json
```

```bash
kubescape policy test ./myrules
kubescape scan ./manifests --custom-rules ./myrules
```

Pass either the parent directory or a single rule directory. The metadata
supplies the rule's name, description, remediation and `match` selectors, so the
rule is only evaluated against the kinds it targets.

A **bare `.rego` file** is also accepted, for a rule with no metadata:

```bash
kubescape scan ./manifests --custom-rules ./myrules/no-root.rego
```

A bare rule is matched against every resource kind, so it must filter input
itself. Prefer a rule directory when the rule targets specific kinds.

Every custom rule becomes a control named `custom-<rule>` in the report.


### Exception Audit

Use `--audit-exceptions --format json` to include an `exceptionAudit` object in scan output. The audit contains:

| Field | Description |
|-------|-------------|
| `summary` | Counts for total, active, expired, matched, unused, and invalid-control exceptions |
| `items` | One entry per loaded exception, including name, status, match count, control IDs, invalid controls, and matched resources when present |
| `generated` | Indicates that the audit was requested and generated |

Item `status` values are `matched`, `unused`, `expired`, and `invalid-control`.

### Examples

```bash
# Scan current cluster
kubescape scan

# Scan with specific framework
kubescape scan framework nsa
kubescape scan framework mitre
kubescape scan framework cis-v1.23-t1.0.1

# Scan specific control
kubescape scan control C-0005 -v

# Scan local files
kubescape scan /path/to/manifests/

# Scan Git repository
kubescape scan https://github.com/org/repo

# Anonymize sensitive report metadata
kubescape scan --hide

# Generate an anonymized JSON report
kubescape scan --hide --format json --output report.json

# The key is used as raw bytes and must be exactly 32 characters long.
# Note: `openssl rand -base64 32` (44 chars) and `openssl rand -hex 32` (64 chars)
# are NOT valid — they exceed 32 bytes once passed through as raw text.
export KUBESCAPE_MASTER_KEY=$(LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom | head -c 32)

# Generate an encrypted JSON report
kubescape scan --encrypt --format json --output encrypted-report.json

# The key is used as raw bytes and must be exactly 32 characters long.
# Note: `openssl rand -base64 32` (44 chars) and `openssl rand -hex 32` (64 chars)
# are NOT valid — they exceed 32 bytes once passed through as raw text.
export KUBESCAPE_MASTER_KEY=$(LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom | head -c 32)

# Decrypt an encrypted report
kubescape decrypt encrypted-report.json > decrypted-report.json

# Output to JSON file
kubescape scan --format json --output results.json

# Set compliance threshold (exit 1 if below). Combine with a framework,
# control, or --view resource|control (see "Score thresholds" below).
kubescape scan framework nsa --compliance-threshold 80
kubescape scan --view resource --compliance-threshold 80

# Exclude namespaces
kubescape scan --exclude-namespaces kube-system,kube-public

# Scan only resources matching a label selector
kubescape scan --label-selector "app=nginx"

# Combine a label selector with a specific framework
kubescape scan framework nsa --label-selector "env=prod,team=backend"

# Set-based label selector using the 'in' operator
kubescape scan framework mitre --label-selector "env in (prod,staging)"
```
### Score thresholds

`--compliance-threshold` (compliance score) applies to the following
invocations:

- `kubescape scan framework <name> ...`
- `kubescape scan control <id> ...`
- `kubescape scan --view resource ...` or `--view control ...`

The default `kubescape scan [path]` uses `--view security`, which does
not evaluate against a score threshold. To gate a pipeline on the
compliance score, use one of the forms above.
`--severity-threshold` and `--fail-coverage-below` apply in every view.

`--fail-coverage-below` gates on the **scan coverage score**, not the raw
ratio of evaluated controls. The score starts from the percentage of controls
that were evaluated and then subtracts a fixed penalty for each runtime gap:
**3 points per silent failed GVR pull** (a resource type that failed to collect
entirely but whose dependent controls still evaluated via other resource types),
**2 points per partial GVR pull**, and **5 points per degraded policy input**
(control configurations or exceptions served from a fallback source). As a
result a scan in which 100% of controls were evaluated can still drop below the
threshold — for example, a single silent failed GVR pull yields a score of 97.

> **Behavior change:** earlier releases compared only the ratio of evaluated
> controls. Pipelines that tuned `--fail-coverage-below` against that narrower
> meaning may now fail on scans that previously passed. Re-check your threshold
> if you rely on this flag in CI.

### OpenTelemetry export

`--otel-endpoint` sends the scan's traces and metrics to any OTLP collector.
Kubescape already instruments its scan pipeline; the flag is what installs the
exporter that makes those spans and metrics leave the process. When neither the
flag nor `OTEL_EXPORTER_OTLP_ENDPOINT` is set, no telemetry SDK is initialised
and the scan behaves exactly as before.

```bash
# Export to a collector listening on the standard gRPC port
kubescape scan --otel-endpoint localhost:4317

# The standard environment variable works too
export OTEL_EXPORTER_OTLP_ENDPOINT=http://collector:4318
export OTEL_EXPORTER_OTLP_PROTOCOL=http/protobuf
kubescape scan
```

A bare `host:port` is sent in plaintext. Use an `https://` URL, or set
`OTEL_EXPORTER_OTLP_INSECURE=false`, to require TLS. `OTEL_EXPORTER_OTLP_PROTOCOL`
selects `grpc` (default) or `http/protobuf`, and `OTEL_SERVICE_NAME` overrides
the reported service name (`kubescape`).

Export failures never change the scan's results or its exit code: they are
logged as a warning and the final flush is bounded, so an unreachable collector
cannot hang a pipeline.

**Spans.** One `kubescape.scan` root span per run, with the pipeline's phases
nested beneath it:

| Span | Phase |
|------|-------|
| `kubescape.scan` | Root span for the whole command |
| `initialization` | Setup, policy download and resource collection |
| `policies` / `policyHandler.getPolicies` | Loading frameworks and controls |
| `resources` / `resourcehandler.CollectResources` | Resource collection |
| `opa testing` / `OPAProcessor.Process` | Control evaluation |
| `prioritization` | Attack-path prioritization |
| `reporting` | Printing results and submission |

**Metrics.** Recorded once per scan, alongside the existing `--format prometheus`
output:

| Metric | Type | Attributes |
|--------|------|------------|
| `kubescape_scan_duration_seconds` | histogram | `kubescape.scan.target` |
| `kubescape_scan_compliance_score` | gauge | `kubescape.scan.target` |
| `kubescape_scan_controls_evaluated_total` | counter | `kubescape.scan.target` |
| `kubescape_scan_controls_total` | counter | `kubescape.scan.target`, `kubescape.control.status`, `kubescape.severity` |
| `kubescape_scan_resources_total` | counter | `kubescape.scan.target`, `k8s.resource.kind` |
| `kubescape_scan_image_vulnerabilities_total` | counter | `kubescape.image`, `kubescape.severity`, `kubescape.vulnerability.fixable` |

`kubescape.vulnerability.fixable` partitions each severity, so summing over it
gives that severity's total rather than double-counting the fixable findings.

Counts describe the full scan. Narrowing the output with `--min-severity` or
`--max-severity` does not change them, matching how the exit-code thresholds are
evaluated.

`kubescape.image` carries one value per scanned image, so a cluster with many
distinct images produces a correspondingly wide series. With `--hide` or
`--encrypt` the image name is dropped and the per-image counts are collapsed
into a single unnamed series, and the host attributes are left off the exported
resource — a run that anonymizes its report does not describe the same things
to the collector in the clear.

---

## kubescape scan framework

Scan against a specific security framework.

### Synopsis

```bash
kubescape scan framework <framework-name> [target] [flags]
```

### Available Frameworks

| Framework | Description |
|-----------|-------------|
| `nsa` | NSA-CISA Kubernetes Hardening Guidance |
| `mitre` | MITRE ATT&CK® for Kubernetes |
| `cis-v1.23-t1.0.1` | CIS Kubernetes Benchmark |
| `soc2` | SOC 2 compliance |
| `pci-dss` | PCI DSS compliance |
| `hipaa` | HIPAA compliance |

### Examples

```bash
kubescape scan framework nsa
kubescape scan framework mitre --include-namespaces production
kubescape scan framework cis-v1.23-t1.0.1 /path/to/manifests
cat ./manifests/deployment.yaml | kubescape scan framework nsa -
```

---

## kubescape scan control

Scan for a specific control.

### Synopsis

```bash
kubescape scan control <control-id> [target] [flags]
```

### Examples

```bash
# Scan for privileged containers
kubescape scan control C-0057 -v

# Scan specific files for a control
kubescape scan control C-0013 /path/to/deployment.yaml

# Scan a manifest from stdin
cat ./manifests/deployment.yaml | kubescape scan control C-0013 -
```

---

## kubescape scan workload

Scan a specific workload.

### Synopsis

```bash
kubescape scan workload <kind>[.<version>[.<group>]]/<name> [`<glob pattern>`/`-`] [flags]
```

Unlike `kubectl`'s `TYPE.VERSION.GROUP` (which takes a plural resource), this command requires a **Kind** (e.g. `Deployment.v1.apps`, not `deployments.v1.apps`).

### Flags

| Flag | Description |
|------|-------------|
| `--namespace <ns>` | Namespace of the workload |
| `--file-path <path>` | Path to a manifest that contains the workload |
| `--chart-path <path>` | Path to the Helm chart the workload is part of. Must be used with `--file-path` |

### Examples

```bash
kubescape scan workload Deployment/nginx --namespace default
kubescape scan workload Deployment.v1.apps/nginx
kubescape scan workload DaemonSet/fluentd --namespace logging
kubescape scan workload Deployment/nginx ./manifests
cat ./manifests/deployment.yaml | kubescape scan workload Deployment/nginx -
kubescape scan workload Deployment/nginx --file-path ./manifests/deployment.yaml
kubescape scan workload Deployment/nginx --chart-path ./chart --file-path ./chart/templates/deployment.yaml
```

---

## kubescape scan image

Scan a container image for vulnerabilities.

### Synopsis

```bash
kubescape scan image <image>:<tag> [flags]
```

### Flags

| Flag | Description |
|------|-------------|
| `--exceptions <path>` | Path to exceptions file |
| `-p, --password <pass>` | Registry password |
| `--platform <platform>` | OCI platform to scan, for example `linux/amd64`, `linux/arm64/v8`, or `windows/amd64` |
| `-u, --username <user>` | Registry username |
| `--use-default-matchers` | Use default vulnerability matchers | `true` |

### Examples

```bash
# Scan public image
kubescape scan image nginx:1.21

# Scan with verbose output
kubescape scan image nginx:1.21 -v

# Scan private registry image
kubescape scan image myregistry.io/myimage:tag -u myuser -p mypass

# Scan the amd64 variant even when Kubescape runs on an ARM machine
kubescape scan image nginx:1.27 --platform linux/amd64
```

See [multi-architecture image scanning](multi-architecture-image-scanning.md) for workload inference, heterogeneous clusters, and CI examples.

---

## kubescape fix

Auto-fix misconfigurations in Kubernetes manifest files.

### Synopsis

```bash
kubescape fix <report-file> [flags]
```

### Flags

| Flag | Description | Default |
|------|-------------|---------|
| `--dry-run` | Preview changes without applying | `false` |
| `--no-confirm` | Apply without confirmation | `false` |
| `--skip-user-values` | Skip changes requiring user values | `true` |

### Examples

```bash
# Generate scan results
kubescape scan /path/to/manifests --format json --output results.json

# Apply fixes
kubescape fix results.json

# Preview fixes
kubescape fix results.json --dry-run

# Apply without prompts
kubescape fix results.json --no-confirm
```

> **Note:** The confirmation prompt requires a real interactive terminal. If
> stdin isn't a TTY — `kubescape fix results.json < /dev/null`, a piped
> answer like `echo y | kubescape fix results.json`, or any CI/script
> context — the prompt is skipped and no changes are applied. Use
> `--no-confirm` to apply fixes in non-interactive contexts.

---

## kubescape patch

Patch container images to fix OS-level vulnerabilities.

### Synopsis

```bash
kubescape patch [flags]
```

### Flags

| Flag | Description | Default |
|------|-------------|---------|
| `-i, --image <image>` | Image to patch (required) | - |
| `-t, --tag <tag>` | Output image tag | `<image>-patched` |
| `-a, --address <address>` | BuildKit daemon address | none (auto-detects local docker daemon, falling back to `unix:///run/buildkit/buildkitd.sock`) |
| `--timeout <duration>` | Patching timeout | `5m` |
| `--ignore-errors` | Continue on errors | `false` |
| `--push` | Push the patched image to the source registry | `false` |
| `-u, --username <user>` | Registry username | - |
| `-p, --password <pass>` | Registry password | - |
| `-f, --format <format>` | Output format: `pretty-printer`, `json`, `sarif` | - |
| `-o, --output <path>` | Output file | stdout |
| `-v, --verbose` | Verbose output | `false` |

### Examples

```bash
# Start buildkitd first
sudo buildkitd &

# Patch an image
sudo kubescape patch --image nginx:1.22

# Custom output tag
sudo kubescape patch --image nginx:1.22 --tag nginx:1.22-fixed

# Verbose output
sudo kubescape patch --image nginx:1.22 -v

# Also push the patched image back to the source registry
sudo kubescape patch --image myregistry.example.com/team/app:1.2.3 --push
```

> By default the patched image is only loaded into the local image store. Pass `--push` if you also want it pushed to the source registry.

---

## Hiding sensitive metadata

Generate a report with anonymized sensitive report metadata.

### Synopsis

```bash
kubescape scan [target] --hide [flags]
```

### Description

Replaces sensitive report metadata with deterministic pseudonyms.

This reduces incidental exposure but is not a confidentiality guarantee.
Values drawn from small or predictable sets (such as common namespace names)
may be recovered by comparing candidate hashes.

Use `--encrypt` when sensitive metadata requires confidentiality.

### Examples

```bash
# Scan the current cluster and generate an anonymized report
kubescape scan --hide --format json --output report.json

# Scan local manifests and save an anonymized report
kubescape scan /path/to/manifests \
  --hide \
  --format json \
  --output report.json
```
> `--hide` replaces sensitive values with deterministic pseudonyms derived from an
> unsalted hash of the original value. Values drawn from a small or guessable set —
> such as common namespace names — can be recovered by hashing candidate values and
> matching the result, and identical values produce identical pseudonyms across
> reports. Use `--hide` to reduce incidental exposure, not as a confidentiality
> guarantee. To share a report whose metadata is genuinely protected, use
> `--encrypt` and withhold the master key.

---

## Encrypting sensitive metadata

Generate a report with encrypted sensitive report metadata.

### Synopsis

```bash
kubescape scan [target] --encrypt [flags]
```

### Description

Encrypts sensitive report metadata using the master key supplied through the
`KUBESCAPE_MASTER_KEY` environment variable.

The master key is used as raw bytes and must be exactly 32 characters long.

Use `--format json` to produce a report that can later be decrypted with
`kubescape decrypt`.

If both `--encrypt` and `--hide` are specified, `--encrypt` takes precedence.

### Examples

```bash
# The key is used as raw bytes and must be exactly 32 characters long.
# Note: `openssl rand -base64 32` (44 chars) and `openssl rand -hex 32` (64 chars)
# are NOT valid — they exceed 32 bytes once passed through as raw text.
export KUBESCAPE_MASTER_KEY=$(LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom | head -c 32)

# Scan the current cluster and generate an encrypted report
kubescape scan \
  --encrypt \
  --format json \
  --output encrypted-report.json

# Scan local manifests and generate an encrypted report
kubescape scan /path/to/manifests \
  --encrypt \
  --format json \
  --output encrypted-report.json
```
> `--encrypt` requires the `KUBESCAPE_MASTER_KEY` environment variable.
> The key must be exactly 32 characters long and the same key must be supplied
> later when running `kubescape decrypt`.

---

## kubescape decrypt

Decrypt an encrypted Kubescape report.

### Synopsis

```bash
kubescape decrypt <report-file>
```

### Description

Decrypts a JSON report that was protected with `kubescape scan --encrypt`.
The command restores encrypted repository metadata, Kubernetes resource
metadata, source paths, container fields, copied resource labels, raw resource
copies in results, and recoverable resource ID references. If ciphertext or an
irreversible legacy resource ID remains, decryption fails instead of returning
a partially restored report.

Only fields encrypted by `kubescape scan --encrypt` are restored.
Metadata pseudonymized with `--hide` cannot be recovered by `kubescape decrypt`.
Older encrypted reports may contain `ref-<hash>` resource IDs that were written
with a one-way mapping. Those IDs cannot be recovered, so the command reports
an error rather than silently treating the report as fully decrypted.

### Flags

| Flag | Description | Default |
|------|-------------|---------|
| `-h, --help` | Help for decrypt | - |

### Examples

```bash
# The key is used as raw bytes and must be exactly 32 characters long.
# Note: `openssl rand -base64 32` (44 chars) and `openssl rand -hex 32` (64 chars)
# are NOT valid — they exceed 32 bytes once passed through as raw text.
export KUBESCAPE_MASTER_KEY=$(LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom | head -c 32)

# Decrypt an encrypted report
kubescape decrypt encrypted-report.json

# Save the decrypted report to a file
kubescape decrypt encrypted-report.json > decrypted-report.json
```

> `kubescape decrypt` restores report fields encrypted by
> `kubescape scan --encrypt`. It does not reverse
> deterministic pseudonymization produced by `--hide`.

---
## kubescape list

List available frameworks and controls.

### Synopsis

```bash
kubescape list <type> [flags]
```

### Types

| Type | Description |
|------|-------------|
| `frameworks` | List available security frameworks |
| `controls` | List available security controls |

### Flags

| Flag | Description | Default |
|------|-------------|---------|
| `--account <id>` | Account ID for custom frameworks | - |
| `--access-key <key>` | Access key | - |
| `--format <format>` | Output format: `pretty-print`, `json`, `yaml`, `csv` | `pretty-print` |

### Examples

```bash
kubescape list frameworks
kubescape list frameworks --format csv
kubescape list controls
kubescape list controls --format json
kubescape list controls --format csv
```

---

## kubescape download

Download artifacts for offline/air-gapped use.

### Synopsis

```bash
kubescape download <type> [name] [flags]
```

### Types

| Type | Description |
|------|-------------|
| `artifacts` | Download all artifacts (frameworks, controls, config) |
| `framework` | Download a specific framework |
| `control` | Download a specific control |

### Flags

| Flag | Description | Default |
|------|-------------|---------|
| `-o, --output <path>` | Output path | `~/.kubescape` |
| `--account <id>` | Account ID | - |
| `--access-key <key>` | Access key | - |

### Examples

```bash
# Download all artifacts
kubescape download artifacts --output /path/to/offline

# Download specific framework
kubescape download framework nsa --output /path/to/nsa.json

# Use downloaded artifacts
kubescape scan --use-artifacts-from /path/to/offline
```

---

## kubescape config

Manage Kubescape configuration.

### Subcommands

| Subcommand | Description |
|------------|-------------|
| `view` | View current configuration |
| `set` | Set configuration value |
| `delete` | Delete cached configuration |

### Examples

```bash
# View configuration
kubescape config view

# View configuration as JSON
kubescape config view -o json

# View configuration as YAML
kubescape config view -o yaml

# Set account ID
kubescape config set accountID <account-id>

# Set cloud report URL
kubescape config set cloudReportURL https://api.example.com

# Delete configuration
kubescape config delete
```

---

## kubescape operator

Interact with the in-cluster Kubescape operator.

### Synopsis

```bash
kubescape operator scan <type> [flags]
```

### Scan Types

| Type | Description |
|------|-------------|
| `configurations` | Trigger configuration scan |
| `vulnerabilities` | Trigger vulnerability scan |

### Examples

```bash
kubescape operator scan configurations
kubescape operator scan vulnerabilities
```

---

## kubescape vap

Manage Kubernetes Validating Admission Policies.

### Subcommands

#### deploy-library

Deploy the Kubescape CEL admission policy library.

```bash
kubescape vap deploy-library | kubectl apply -f -
```

#### create-policy-binding

Create a ValidatingAdmissionPolicyBinding.

```bash
kubescape vap create-policy-binding [flags]
```

**Flags:**

| Flag | Description | Required |
|------|-------------|----------|
| `-n, --name <name>` | Binding name | Yes |
| `-p, --policy <id>` | Policy/control ID | Yes |
| `--namespace <ns>` | Namespace selector (repeatable) | No |
| `--label <k=v>` | Label selector (repeatable) | No |
| `-a, --action <action>` | Action: `Deny`, `Audit`, `Warn` | No (default: `Deny`) |
| `-r, --parameter-reference <name>` | Parameter reference | No |

### Examples

```bash
# Deploy policy library
kubescape vap deploy-library | kubectl apply -f -

# Create binding
kubescape vap create-policy-binding \
  --name deny-privileged \
  --policy c-0057 \
  --namespace production \
  --action Deny | kubectl apply -f -
```

---

## kubescape mcpserver

Start the MCP (Model Context Protocol) server for AI assistant integration.

### Synopsis

```bash
kubescape mcpserver
```

### Description

Starts an MCP server that exposes Kubescape data to AI assistants. The server communicates via stdio.

### Prerequisites

- Kubescape operator installed in the cluster
- kubectl configured with cluster access

### Examples

```bash
# Start MCP server
kubescape mcpserver
```

### Claude Desktop Configuration

```json
{
  "mcpServers": {
    "kubescape": {
      "command": "kubescape",
      "args": ["mcpserver"]
    }
  }
}
```

---

## kubescape version

Display version information.

### Synopsis

```bash
kubescape version [--format text|json]
```

### Flags

| Flag | Short | Default | Description |
|---|---|---|---|
| `--format` | `-f` | `text` | Output format. Supported: `text`, `json` |

### Examples

```bash
# Default human-readable output
kubescape version

# Machine-readable JSON output (safe to pipe to jq)
kubescape version --format json
# {"version":"v3.x.x","commit":"abc123","date":"2024-01-15"}
```

---

## kubescape completion

Generate shell completion scripts.

### Synopsis

```bash
kubescape completion <shell>
```

### Supported Shells

- `bash`
- `zsh`
- `fish`
- `powershell`

### Examples

```bash
# Bash
kubescape completion bash > /etc/bash_completion.d/kubescape

# Zsh
kubescape completion zsh > "${fpath[1]}/_kubescape"

# Fish
kubescape completion fish > ~/.config/fish/completions/kubescape.fish
```

---

## Environment Variables

Kubescape respects the following environment variables:

| Variable | Description |
|----------|-------------|
| `KS_ACCOUNT` | Default account ID |
| `KS_CACHE_DIR` | Cache directory path |
| `KS_EXCLUDE_NAMESPACES` | Default namespaces to exclude |
| `KS_INCLUDE_NAMESPACES` | Default namespaces to include |
| `KS_FORMAT` | Default output format |
| `KS_LOGGER` | Log level |
| `KS_LOGGER_NAME` | Logger name |
| `KUBECONFIG` | Path to kubeconfig file |
| `KUBESCAPE_MASTER_KEY` | 32-character master key used to encrypt and decrypt report metadata |
| `HTTPS_PROXY` | HTTPS proxy URL |
| `HTTP_PROXY` | HTTP proxy URL |
| `NO_PROXY` | Hosts to exclude from proxy |

---

## Exit Codes

| Code | Description |
|------|-------------|
| `0` | Success |
| `1` | Failure (threshold exceeded, scan failed, etc.) |

---

## See Also

- [Getting Started Guide](getting-started.md)
- [Architecture](architecture.md)
- [Troubleshooting](troubleshooting.md)
- [MCP Server Documentation](mcp-server.md)
