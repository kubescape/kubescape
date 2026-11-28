---
name: kubescape-mcp
description: Start and use the Kubescape MCP server (kubescape mcpserver) so assistants can query cluster vulnerability manifests, configuration scan data, run scoped security scans, and related tools over the Model Context Protocol.
license: Apache-2.0
compatibility: Requires the kubescape CLI on PATH. Most cluster-backed tools need the Kubescape operator installed and kubectl access; local IaC tools benefit from --workspace containment.
metadata:
  author: kubescape
  version: "0.1.0"
---

# Kubescape MCP server

This repository ships `kubescape mcpserver` (see `cmd/mcpserver` and `docs/mcp-server.md`). The plugin bundles it via `.mcp.json` as a stdio MCP server running `kubescape mcpserver`.

## Start the server

```bash
# Default: stdio transport (MCP clients)
kubescape mcpserver

# Restrict local/IaC scans to a project root (also: KUBESCAPE_WORKSPACE_DIR)
kubescape mcpserver --workspace /path/to/project

# HTTP SSE on loopback only (default port 8080)
kubescape mcpserver --transport sse --port 8080 --workspace /path/to/project
```

Flags: `--transport` / `-t` (`stdio` or `sse`), `--port` / `-p` (SSE), `--workspace`.

## Operator data

Cluster query tools read Custom Resources from the Kubescape operator (vulnerability and configuration scanning). Install/enable per `docs/mcp-server.md` (Helm chart `kubescape/kubescape-operator` with vulnerability and configuration scan capabilities). Confirm data exists before expecting rich answers:

```bash
kubectl -n kubescape get vulnerabilitymanifests
kubectl get workloadconfigurationscansummaries -A
```

Full configuration scan manifests need continuous scanning enabled on the operator.

## What agents should do

1. Prefer MCP tools when the server is connected instead of re-deriving CR queries by hand.
2. For large scan tools (`run_framework_security_scan`, `run_rbac_security_scan`, `run_network_security_scan`, `scan_controls`, `scan_workload`, `scan_local_iac`, `scan_local_iac_controls`, `scan_manifest`), follow pagination: use `scan_id` + `next_offset` with `get_scan_results` in the **same MCP session** until `next_offset` is absent. Snapshots expire (~10 minutes) and are process-local. If a scan exceeds the retention budget, the server returns the first page and `pagination_warning` without `next_offset` — report the incomplete result and narrow the scan scope; do not treat that page as complete.
3. With `--workspace` set, local paths must stay inside that root; `../` or escaping symlinks return `INVALID_ARGUMENT`.
4. If operator CRs are missing, say so clearly and fall back to CLI `kubescape scan` / `kubescape fix` skills for offline manifest work.
5. Do not invent tool names — discover tools from the live MCP session and match `docs/mcp-server.md`.

## Plugin MCP config

`.mcp.json` runs:

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

Add `--workspace` (or set `KUBESCAPE_WORKSPACE_DIR`) in the client config when local IaC scans should be contained.
