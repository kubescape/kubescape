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
| `--compliance-threshold <float>` | Fail if compliance score is below threshold | `0` |
| `--controls-config <path>` | Path to controls configuration file | - |
| `-e, --exclude-namespaces <ns>` | Namespaces to exclude (comma-separated) | - |
| `--exceptions <path>` | Path to exceptions file | - |
| `-f, --format <format>` | Output format: `pretty-printer`, `json`, `junit`, `sarif`, `html`, `pdf`, `prometheus` | `pretty-printer` |
| `--include-namespaces <ns>` | Namespaces to include (comma-separated) | - |
| `--keep-local` | Don't report results to backend | `false` |
| `--kubeconfig <path>` | Path to kubeconfig file | - |
| `-o, --output <path>` | Output file path | stdout |
| `--scan-images` | Also scan container images for vulnerabilities | `false` |
| `--severity-threshold <sev>` | Fail if findings at or above severity: `low`, `medium`, `high`, `critical` | - |
| `--submit` | Submit results to Kubescape SaaS | `false` |
| `--use-artifacts-from <path>` | Load artifacts from local directory (offline mode) | - |
| `--use-from <path>` | Load specific policy from path | - |
| `-v, --verbose` | Display all resources, not just failed ones | `false` |
| `--view <type>` | View type: `security`, `control`, `resource` | `security` |

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

# Output to JSON file
kubescape scan --format json --output results.json

# Set compliance threshold (exit 1 if below)
kubescape scan --compliance-threshold 80

# Exclude namespaces
kubescape scan --exclude-namespaces kube-system,kube-public
```

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
```

---

## kubescape scan workload

Scan a specific workload.

### Synopsis

```bash
kubescape scan workload <kind>/<name> [flags]
```

### Flags

| Flag | Description |
|------|-------------|
| `--namespace <ns>` | Namespace of the workload |

### Examples

```bash
kubescape scan workload Deployment/nginx --namespace default
kubescape scan workload DaemonSet/fluentd --namespace logging
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
```

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
| `-a, --addr <addr>` | BuildKit daemon address | `unix:///run/buildkit/buildkitd.sock` |
| `--timeout <duration>` | Patching timeout | `5m` |
| `--ignore-errors` | Continue on errors | `false` |
| `-u, --username <user>` | Registry username | - |
| `-p, --password <pass>` | Registry password | - |
| `-f, --format <format>` | Output format | - |
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
```

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
| `--format <format>` | Output format: `pretty-print`, `json` | `pretty-print` |

### Examples

```bash
kubescape list frameworks
kubescape list controls
kubescape list controls --format json
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
kubescape version
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