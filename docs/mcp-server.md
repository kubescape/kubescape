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

## Related Documentation

- [Kubescape Operator Installation](https://kubescape.io/docs/operator/)
- [Vulnerability Scanning](https://kubescape.io/docs/vulnerabilities/)
- [Configuration Scanning](https://kubescape.io/docs/configuration-scanning/)
- [MCP Protocol Specification](https://modelcontextprotocol.io/)