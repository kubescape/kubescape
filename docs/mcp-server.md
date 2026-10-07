# Kubescape MCP Server

The Kubescape MCP (Model Context Protocol) Server enables AI assistants to query your Kubernetes cluster's security posture using natural language. It exposes Kubescape's vulnerability and configuration scan data through the [MCP protocol](https://modelcontextprotocol.io/).

## Overview

The MCP server allows AI assistants (like Claude, ChatGPT, or custom AI tools) to:

- List and query vulnerability manifests for images and workloads
- Retrieve CVE details and vulnerability matches
- Access configuration security scan results
- Provide security recommendations based on real cluster data

## Prerequisites

Before using the MCP server, you need:

1. **Kubescape Operator installed in your cluster** - The MCP server reads data from Custom Resources created by the operator
2. **kubectl configured** - With access to the cluster running the Kubescape operator
3. **Kubescape CLI** - Version 3.x or later

### Installing the Kubescape Operator

```bash
helm repo add kubescape https://kubescape.github.io/helm-charts/
helm repo update

helm upgrade --install kubescape kubescape/kubescape-operator \
  --namespace kubescape \
  --create-namespace \
  --set capabilities.vulnerabilityScan=enable \
  --set capabilities.configurationScan=enable
```

Wait for the operator to complete initial scans:

```bash
kubectl -n kubescape get vulnerabilitymanifests
kubectl -n kubescape get workloadconfigurationscans
```

## Starting the MCP Server

```bash
kubescape mcpserver
```

The server starts and communicates via stdio, making it compatible with MCP-enabled AI tools.

## Available Tools

The MCP server exposes the following tools to AI assistants:

### Vulnerability Tools

#### `list_vulnerability_manifests`

Discover available vulnerability manifests at image and workload levels.

**Parameters:**
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `namespace` | string | No | Filter by namespace |
| `level` | string | No | Type of manifests: `"image"`, `"workload"`, or `"both"` (default) |

**Example Response:**
```json
{
  "vulnerability_manifests": {
    "manifests": [
      {
        "type": "workload",
        "namespace": "default",
        "manifest_name": "deployment-nginx-nginx",
        "image-level": false,
        "workload-level": true,
        "image-id": "sha256:abc123...",
        "image-tag": "nginx:1.21",
        "resource_uri": "kubescape://vulnerability-manifests/default/deployment-nginx-nginx"
      }
    ]
  }
}
```

#### `list_vulnerabilities_in_manifest`

List all vulnerabilities (CVEs) found in a specific manifest.

**Parameters:**
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `namespace` | string | No | Namespace of the manifest (default: `"kubescape"`) |
| `manifest_name` | string | Yes | Name of the manifest |

**Example Response:**
```json
[
  {
    "id": "CVE-2023-12345",
    "severity": "High",
    "description": "Buffer overflow in libfoo",
    "fix": {
      "versions": ["1.2.4"],
      "state": "fixed"
    }
  }
]
```

#### `list_vulnerability_matches_for_cve`

Get detailed information about a specific CVE in a manifest, including affected packages and fix information.

**Parameters:**
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `namespace` | string | No | Namespace of the manifest (default: `"kubescape"`) |
| `manifest_name` | string | Yes | Name of the manifest |
| `cve_id` | string | Yes | CVE identifier (e.g., `"CVE-2023-12345"`) |

### Configuration Tools

#### `list_configuration_security_scan_manifests`

Discover available security configuration scan results at the workload level.

**Parameters:**
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `namespace` | string | No | Filter by namespace (default: `"kubescape"`) |

**Example Response:**
```json
{
  "configuration_manifests": {
    "manifests": [
      {
        "namespace": "default",
        "manifest_name": "deployment-nginx",
        "resource_uri": "kubescape://configuration-manifests/default/deployment-nginx"
      }
    ]
  }
}
```

#### `get_configuration_security_scan_manifest`

Get detailed configuration scan results for a specific workload, including failed controls and remediation guidance.

**Parameters:**
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `namespace` | string | No | Namespace of the manifest (default: `"kubescape"`) |
| `manifest_name` | string | Yes | Name of the configuration manifest |

### Live Scanning Tools

#### `run_framework_security_scan`

Run an on-demand, live Framework security scan (e.g. nsa, mitre) and return the failed resources along with the compliance score. Check the `degraded` flag in the response to ensure the scan fully completed (e.g. no control timeouts). Note that `compliance_score` is optional and may be omitted if the scan produces no framework summary. The `failed_resources` array is truncated at 100 entries; check `truncated`, `total_failed`, and `returned_failed` to understand if the list is partial.

**Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `framework_name` | string | Yes | Name of the framework to scan (e.g. nsa, mitre, cis-v1.23-t1.0.1) |
| `namespace` | string | No | Namespace to scope the Framework scan (optional, defaults to cluster-wide if omitted) |

**Example Response:**
```json
{
  "compliance_score": 0,
  "framework_name": "nsa",
  "degraded": true,
  "not_evaluated_controls": 8,
  "total_controls": 24,
  "total_failed": 5,
  "returned_failed": 5,
  "truncated": false,
  "failed_resources": [{}, {}, {}, {}, {}]
}
```

#### `run_rbac_security_scan`

Run an on-demand, live RBAC security scan (evaluating RBAC-related controls) and return the failed resources. The `failed_resources` array is truncated at 100 entries; check `truncated`, `total_failed`, and `returned_failed` to understand if the list is partial.

**Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `namespace` | string | No | Namespace to scope the RBAC scan (optional, defaults to cluster-wide if omitted) |

**Example Response:**
```json
{
  "degraded": false,
  "not_evaluated_controls": 0,
  "total_controls": 2,
  "total_failed": 1,
  "returned_failed": 1,
  "truncated": false,
  "failed_resources": [{}]
}
```

#### `run_network_security_scan`

Run an on-demand, live Network security scan (evaluating network-related controls) and return the failed resources. The `failed_resources` array is truncated at 100 entries; check `truncated`, `total_failed`, and `returned_failed` to understand if the list is partial.

**Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `namespace` | string | No | Namespace to scope the Network scan (optional, defaults to cluster-wide if omitted) |

**Example Response:**
```json
{
  "degraded": false,
  "not_evaluated_controls": 0,
  "total_controls": 1,
  "total_failed": 0,
  "returned_failed": 0,
  "truncated": false,
  "failed_resources": []
}
```

#### `scan_workload`

Scan a single named Kubernetes workload for misconfigurations and return its failed controls. Prefer this over `scan_controls` or `run_framework_security_scan` once you know which workload you care about: only the rules whose match criteria cover that resource's kind are evaluated, and the queries they need are scoped to the workload's namespace, so the scan is much cheaper and the response much smaller than a namespace-wide one.

By default the workload is fetched from the live cluster. Pass `path` to resolve it from local manifests instead. The two modes differ in how the workload is located:

* **Live cluster** — the kind is resolved through Kubernetes discovery, so a bare kind such as `Deployment/nginx` is enough for built-in types. A custom resource must spell out its version and group (`Widget.v1.example.com/my-widget`), because discovery cannot disambiguate it otherwise. Scanning a `Secret` is refused.
* **Local manifests** — resources are matched on kind and name (plus namespace and apiVersion when given) with no cluster involved, so no discovery and no CRD resolution. If more than one manifest matches, the scan reports the ambiguity rather than picking one; add a namespace to disambiguate.

A workload that is owned by another resource — a Pod belonging to a ReplicaSet, say — is rejected. Scan the owner instead.

**Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `workload` | string | Yes | Workload identifier as `<kind>[.<version>[.<group>]]/<name>`, optionally namespace-qualified: `"Deployment/nginx"`, `"default/Deployment/nginx"`, or `"Deployment.v1.apps/nginx"` |
| `namespace` | string | No | Namespace of the workload (optional; defaults to `'default'` for live-cluster scans, or unconstrained when `path` is given). Pass `"*"` to search across all namespaces in a live cluster (requires cluster-wide list permissions). Must not conflict with a namespace prefix in the workload identifier |
| `path` | string | No | Path to local YAML manifests. When set, the workload is resolved from those files instead of the live cluster |
| `framework` | string | No | Framework to scan against (optional, defaults to the full workload control set) |

**Example Response:**
```json
{
  "degraded": false,
  "not_evaluated_controls": 0,
  "total_controls": 16,
  "total_failed": 1,
  "returned_failed": 1,
  "truncated": false,
  "failed_resources": [{}]
}
```

#### `scan_container_image`

Run an on-demand container image vulnerability scan and return structured JSON containing deduplicated vulnerabilities, severity counts, and optional match details.

**Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `image_name` | string | Yes | Name of the remote container image to scan (e.g. `"nginx:alpine"`) |
| `username` | string | No | Username for registry authentication (optional) |
| `password` | string | No | Password for registry authentication (optional) |
| `include_matches` | boolean | No | Include detailed match location and package info for each vulnerability (optional, default: `false`) |
| `severity` | string | No | Filter vulnerabilities by minimum severity (e.g. `"Low"`, `"Medium"`, `"High"`, `"Critical"`) |

**Example Response:**
```json
{
  "image": "nginx:alpine",
  "total_vulnerabilities": 1,
  "severities": {
    "Critical": 1
  },
  "vulnerabilities": [
    {
      "id": "CVE-2023-12345",
      "severity": "Critical",
      "package": {
        "name": "libssl",
        "version": "1.1.1"
      }
    }
  ]
}
```

### Report Comparison Tools

#### `diff_reports`

Compare two already-produced Kubescape scan report files (JSON) and return what changed, reusing the same comparison engine as `kubescape diff`/`--baseline`. Works for posture reports (`kubescape scan --format json`), reporting new, resolved, unchanged, and incomparable control failures, and for image vulnerability reports (`kubescape scan image --format json`), reporting new, resolved, and unchanged CVEs. Both reports must be the same kind; comparing a posture report against a vulnerability report is rejected rather than silently treated as comparable.

**Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `base_report` | string | Yes | Path to the baseline/base Kubescape scan report JSON file |
| `head_report` | string | Yes | Path to the current/head Kubescape scan report JSON file |

**Example use case:** "What changed between these two Kubescape reports?"

**Example Response (posture reports):**
```json
{
  "kind": "posture",
  "base_report": "base.json",
  "head_report": "head.json",
  "posture": {
    "new": [{"resourceID": "...", "controlID": "C-0001", "severity": "High", "baseStatus": "passed", "headStatus": "failed"}],
    "resolved": [],
    "unchanged": [],
    "incomparable": []
  }
}
```

**Example Response (image vulnerability reports):**
```json
{
  "kind": "vulnerability",
  "base_report": "base-image.json",
  "head_report": "head-image.json",
  "vulnerability": {
    "baseImages": ["app:1.0"],
    "headImages": ["app:1.1"],
    "new": [{"id": "CVE-NEW-HIGH", "severity": "High", "package": "curl", "version": "1.0"}],
    "resolved": [{"id": "CVE-OLD", "severity": "High", "package": "openssl", "version": "3.0.1"}],
    "unchanged": []
  }
}
```

### Compliance & Hardening Tools

#### `predict_pss_compliance`

Predict which workloads in a namespace would fail Pod Security Standards (PSS v1.37) enforcement at a given level (`Privileged`, `Baseline`, or `Restricted`) and report exactly what violates per container. Use this to assess blast radius before enabling PSS admission enforcement — answers *"what would break if I enforced Baseline/Restricted on this namespace?"* without touching the cluster's admission configuration.

**Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `namespace` | string | Yes | Namespace to analyze |
| `level` | string | No | Target PSS level: `Privileged`, `Baseline`, or `Restricted` (default: `Restricted`) |
| `workload_name` | string | No | Specific workload to check (`Kind/Name` or bare `Name`). Omit to evaluate all workloads in the namespace |

**Example Response:**

```json
{
  "namespace": "production",
  "target_level": "Restricted",
  "summary": {
    "total_workloads": 12,
    "passing": 11,
    "failing": 1,
    "current_effective_level": "Baseline"
  },
  "failing_workloads": [
    {
      "kind": "Deployment",
      "name": "legacy-api",
      "passes_at": "Baseline",
      "violations": [
        {
          "check": "Capabilities",
          "container": "main",
          "level": "Restricted",
          "description": "container 'main' must drop ALL capabilities; securityContext.capabilities is unset"
        },
        {
          "check": "RunAsNonRoot",
          "container": "main",
          "level": "Restricted",
          "description": "container 'main' must set runAsNonRoot to true"
        }
      ]
    }
  ]
}
```

## Resource Templates

The MCP server also exposes resource templates for direct access to data:

### Vulnerability Manifest
```
kubescape://vulnerability-manifests/{namespace}/{manifest_name}
```

### Configuration Manifest
```
kubescape://configuration-manifests/{namespace}/{manifest_name}
```

## Integration with AI Assistants

### Claude Desktop

Add to your Claude Desktop configuration (`~/.config/claude/config.json` on Linux or `~/Library/Application Support/Claude/claude_desktop_config.json` on macOS):

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

### Custom Integration

For custom AI applications using the MCP SDK:

```python
from mcp import Client

async with Client("kubescape", ["kubescape", "mcpserver"]) as client:
    # List vulnerability manifests
    result = await client.call_tool(
        "list_vulnerability_manifests",
        {"level": "workload"}
    )
    print(result)
```

## Example AI Queries

Once connected, you can ask your AI assistant questions like:

- "What vulnerabilities exist in my production namespace?"
- "Show me all critical CVEs affecting my nginx deployments"
- "What configuration issues does my cluster have?"
- "Which workloads have the most security issues?"
- "Give me details about CVE-2023-12345 in my cluster"
- "What changed between these two Kubescape reports?"

## Troubleshooting

### No vulnerability manifests found

Ensure the Kubescape operator has completed vulnerability scanning:

```bash
kubectl -n kubescape get vulnerabilitymanifests
```

If empty, check operator logs:

```bash
kubectl -n kubescape logs -l app=kubescape
```

### Connection issues

Verify your kubeconfig is correctly configured:

```bash
kubectl get nodes
```

### MCP server not responding

Check that you're running Kubescape v3.x or later:

```bash
kubescape version
```

## Security Considerations

- The MCP server runs with the same Kubernetes permissions as your kubeconfig
- It provides read-only access to vulnerability and configuration data
- No cluster modifications are made through the MCP server
- Consider running with a service account that has limited permissions in production
- **SSE Transport**: `kubescape mcpserver -t sse` listens on `127.0.0.1` only and answers `403 Forbidden` to any request whose `Origin` header names a site other than this machine, so web pages open in your browser cannot reach the server. MCP clients that are not browsers send no `Origin` header and are not affected; browser-based clients must be served from `localhost` or a loopback address.
- **Credential Handling**: The `scan_container_image` tool accepts optional registry credentials (`username` and `password`). Be aware that parameters supplied to MCP tools may be retained in client conversation logs or model contexts depending on your client environment.
- **Image Reference Validation**: The `scan_container_image` tool validates image names as remote image references and rejects local file paths and scheme prefixes (such as `dir:`, `file:`, `sbom:`) to prevent unauthorized local filesystem access.
- **Air-Gapped Environments**: In air-gapped environments, set the `KS_GRYPE_LISTING_URL` environment variable to point to your internal Grype vulnerability database mirror listing URL.

## Related Documentation

- [Kubescape Operator Installation](https://kubescape.io/docs/operator/)
- [Vulnerability Scanning](https://kubescape.io/docs/vulnerabilities/)
- [Configuration Scanning](https://kubescape.io/docs/configuration-scanning/)
- [MCP Protocol Specification](https://modelcontextprotocol.io/)