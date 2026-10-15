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

### Remediation Tools

#### `apply_remediation`

Compute the deterministic YAML patch Kubescape's fixer plans for failed controls, from either local IaC (`path`) or an existing posture report (`report_path`), which may be a live-cluster report. It reuses the same fixer as `kubescape fix`; it does not implement a second remediation engine.

This tool only plans. It does not modify any file, and it does not change the cluster. The patched YAML it returns is for the caller to write or apply.

**Parameters:**

| Parameter     | Type            | Required                                    | Description                                                                         |
| ------------- | --------------- | ------------------------------------------- | ----------------------------------------------------------------------------------- |
| `path`        | string          | One of `path` / `report_path`               | Local YAML file or directory to scan and remediate                                  |
| `report_path` | string          | One of `path` / `report_path`               | Path to a posture report JSON file (`kubescape scan --format json`). No scan is run |
| `base_path`   | string          | With `report_path`, for file-backed reports | Directory the report's files must stay inside. Not allowed with `path`              |
| `control_ids` | string or array | Yes                                         | Control IDs to remediate, e.g. `"C-0013,C-0017"` or `["C-0013"]`                    |

Exactly one of `path` and `report_path` must be given. Existing callers that pass `path` and `control_ids` are unaffected.

**Report input and `base_path`:**

- A report of a file, directory or git scan names, inside itself, where its manifests are. Because a report may come from another party, `base_path` is required for these and every file the fixer reads must resolve inside it. `base_path`, the report's own recorded location and symlinks are all resolved before they are compared, so `..` and symlinks cannot widen it. The report's own directory is not used as a default, because a report is routinely written somewhere other than the tree it scanned.
- A cluster report has no files, so `base_path` is not used and is ignored if given.
- The report is read once, and must be a regular file of at most 64 MiB.
- Findings that are not for the controls in `control_ids` are left out.

**Response fields:**

| Field                     | Description                                                                                                                                                                                    |
| ------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `files`                   | Patched YAML per manifest file. Always `[]` for a cluster report                                                                                                                               |
| `rendered_manifests`      | Patched manifest per live-cluster resource, sorted by `resource_id`. Always `[]` for a file-backed report. These are rendered from the scanned object; nothing has been applied to the cluster |
| `fixed_control_instances` | Count of (resource, control) pairs the fixer remediated                                                                                                                                        |
| `unfixed_controls`        | Controls with no automatic fix, with the fixer's reason, plus any requested control the scan did not evaluate                                                                                  |
| `degraded`                | The scan behind the report did not fully complete. An empty result on a degraded run is not "everything is compliant"                                                                          |
| `items`                   | One entry per failed (resource, control) pair, sorted by `resource_id` then control ID. Always present                                                                                         |
| `report`                  | Bounded summary of the report's scan coverage                                                                                                                                                  |
| `warnings`                | Notes about the run, for example that the report carries no coverage information                                                                                                               |

**Each entry in `items`:**

| Field            | Description                                                                                                                                                                                                                                                    |
| ---------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `resource_id`    | The report's opaque resource identifier. It is the identity of the item and must not be parsed: it can be a composite RBAC chain. Empty for `not_evaluated`                                                                                                    |
| `resource`       | `kind`, `name` and `namespace` from the report, when it has the resource. `namespace` is `""` when the object has none. Two resources can share these three values and still be distinct                                                                       |
| `control`        | `id` and `name`                                                                                                                                                                                                                                                |
| `evidence`       | The report's own rule results for the control: rule name, status, and the paths as recorded (`failed_path`, `review_path`, `delete_path`, `fix_path`, `fix_value`). Bounded to 20 rules and 20 paths per rule; `evidence_truncated` / `paths_truncated` say so |
| `classification` | See below                                                                                                                                                                                                                                                      |
| `reason`         | The fixer's reason, verbatim, for anything other than `patch_available`                                                                                                                                                                                        |
| `file_path`      | The manifest the resource was read from. Absent for a cluster resource                                                                                                                                                                                         |

**`classification`:**

| Value             | Meaning                                                                                                                        |
| ----------------- | ------------------------------------------------------------------------------------------------------------------------------ |
| `patch_available` | The fixer counted the control as remediated by the patch it planned for the resource                                           |
| `partial_patch`   | Some of the control's failed paths are covered by the resource's patch and others are not. The control still needs manual work |
| `manual`          | The fixer produced no remediation. `reason` says why                                                                           |
| `not_evaluated`   | The control was requested but the scan never evaluated it, so nothing is known about the resources it would flag               |

Classification comes from the fixer, never from whether a `fix_path` is present. A control can carry a `fix_path` and still be `manual`: the fixer declines a resource it cannot patch faithfully, for example one owned by another resource (fix its owner), a workload whose container environment the scan redacted (a rendered manifest would overwrite the real values), a Secret or ConfigMap, a finding that spans several objects such as an RBAC chain, or a fix that needs a value only the caller can supply.

`patch_available` is a statement about the resource's patch as a whole. The fixer plans one patch per resource and may count a control as covered because another control's expression changes the same path, so it does not mean an expression exists that is specific to that control.

A fix whose value is a `YOUR_...` placeholder is still planned and counted, because the calling agent is the party that can substitute a real value. Check `applied_expressions` (file-backed) or the rendered manifest (cluster) before applying anything.

**`report`:**

| Field                                                             | Description                                                                                           |
| ----------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------- |
| `kind`                                                            | `cluster`, `directory`, `file`, `git` or `unknown`                                                    |
| `coverage_available`                                              | `false` when the report has no `scanCoverage`; the counters below then say nothing about completeness |
| `degraded`                                                        | The report's own degraded flag                                                                        |
| `evaluated_controls`, `total_controls`                            | Controls evaluated, and in scope                                                                      |
| `not_evaluated_control_ids`, `not_evaluated_control_count`        | At most 50 sorted IDs, and the full count                                                             |
| `failed_gvr_pulls`, `silent_failed_gvr_count`, `unexamined_kinds` | Counts only; the lists are not copied                                                                 |

A report file does not carry the `truncated` flag of the `run_framework_security_scan` response, so this tool cannot tell whether a failed-resource list was truncated before the report was written. Do not read an absent flag as completeness.

**Example Response (cluster report, `control_ids` = `C-0057,C-0041`):**

```json
{
  "files": [],
  "fixed_control_instances": 1,
  "degraded": true,
  "unfixed_controls": [
    {
      "ControlID": "C-0041",
      "ControlName": "HostNetwork access",
      "ResourceName": "nginx",
      "ResourceKind": "Deployment",
      "FilePath": "cluster",
      "ResourceID": "apps/v1/default/Deployment/nginx",
      "DocumentIndex": 0,
      "Reason": "no auto-fix available for this control"
    }
  ],
  "items": [
    {
      "resource_id": "apps/v1/default/Deployment/nginx",
      "resource": {
        "kind": "Deployment",
        "name": "nginx",
        "namespace": "default"
      },
      "control": { "id": "C-0041", "name": "HostNetwork access" },
      "evidence": [
        {
          "rule": "rule-no-fix",
          "status": "failed",
          "paths": [{ "failed_path": "spec.hostNetwork" }]
        }
      ],
      "classification": "manual",
      "reason": "no auto-fix available for this control"
    },
    {
      "resource_id": "apps/v1/default/Deployment/nginx",
      "resource": {
        "kind": "Deployment",
        "name": "nginx",
        "namespace": "default"
      },
      "control": { "id": "C-0057", "name": "Privileged container" },
      "evidence": [
        {
          "rule": "rule-spec.template.spec.containers[0].securityContext.privileged",
          "status": "failed",
          "paths": [
            {
              "fix_path": "spec.template.spec.containers[0].securityContext.privileged",
              "fix_value": "false"
            }
          ]
        }
      ],
      "classification": "patch_available"
    }
  ],
  "rendered_manifests": [
    {
      "resource_id": "apps/v1/default/Deployment/nginx",
      "manifest": "apiVersion: apps/v1\nkind: Deployment\n..."
    }
  ],
  "report": {
    "kind": "cluster",
    "coverage_available": true,
    "degraded": true,
    "evaluated_controls": 20,
    "total_controls": 22,
    "not_evaluated_control_ids": ["C-0069"],
    "not_evaluated_control_count": 1,
    "failed_gvr_pulls": 1,
    "silent_failed_gvr_count": 3,
    "unexamined_kinds": 2
  }
}
```

**Errors:** `INVALID_ARGUMENT` for a missing, conflicting, unreadable, oversized or non-report input, or a report whose recorded scan location is outside `base_path`. A single resource whose manifest resolves outside `base_path` is not an error: it is skipped and reported as `manual`.

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

#### `detect_secret_exposure`

Detect potential secret exposure in Kubernetes workloads and ConfigMaps within a namespace. Analyzes container environment variables, `envFrom` configurations, and `ConfigMap` data for exposed plain-text credentials and high-confidence secret patterns (such as AWS keys, GitHub tokens, Slack tokens, private keys, JWTs, and database URIs with credentials). Masked previews are provided to prevent credential leakage. If listing ConfigMaps is forbidden (RBAC) during a workload-scoped scan, `configMapReferencesResolved` is set to `false` and a warning indicates that `envFrom` and `configMapKeyRef` references could not be evaluated. Other ConfigMap list errors return a tool error.

**Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `namespace` | string | Yes | Namespace to analyze |
| `resource_kind` | string | No | Filter by resource kind: `Deployment`, `DaemonSet`, `StatefulSet`, `ReplicaSet`, `Job`, `CronJob`, `Pod`, `ConfigMap` |
| `resource_name` | string | No | Specific resource name to check. Omit to evaluate all supported resources in the namespace |

**Example Response:**

```json
{
  "namespace": "production",
  "totalWorkloads": 5,
  "totalConfigMaps": 3,
  "findingsCount": 2,
  "findings": [
    {
      "resourceKind": "Deployment",
      "resourceName": "backend-api",
      "namespace": "production",
      "container": "api-server",
      "location": "env.DB_PASSWORD",
      "key": "DB_PASSWORD",
      "ruleId": "ENV_CREDENTIAL_KEYWORD",
      "description": "Plain-text credential configured directly in configuration data",
      "maskedValue": "supe****123!",
      "severity": "High"
    },
    {
      "resourceKind": "ConfigMap",
      "resourceName": "app-config",
      "namespace": "production",
      "location": "data.id_rsa",
      "key": "id_rsa",
      "ruleId": "CONFIGMAP_SENSITIVE_KEY",
      "description": "ConfigMap data key indicates credential or sensitive secret file",
      "maskedValue": "-----BEGIN PRIVATE KEY...[REDACTED]-----",
      "severity": "High"
    }
  ],
  "configMapReferencesResolved": true
}
```

##### Relationship to Control C-0012 (`Applications credentials in configuration files`)

`detect_secret_exposure` complements Kubescape posture control C-0012 with interactive, live-cluster secret exposure detection. While both share the core objective of identifying exposed credentials in Kubernetes configurations, the MCP tool deliberately differs in several areas to improve signal quality and detection depth for AI assistants:

| Capability / Behavior | Posture Control C-0012 | `detect_secret_exposure` MCP Tool |
|-----------------------|------------------------|-----------------------------------|
| **Workload & ConfigMap Cross-Referencing** | Evaluates resources in isolation. Skips `envFrom` and ignores `valueFrom.configMapKeyRef` references (`is_not_reference` check). | **Actively resolves references across resources.** Traces container `envFrom.configMapRef` to ConfigMaps containing exposed secrets (`ENVFROM_EXPOSED_CONFIGMAP`) and validates `configMapKeyRef` targets (`CONFIGMAP_KEY_REF_CREDENTIAL`). |
| **High-Confidence Value Detection** | Generic substring matching (`_key_`, `_secret_`, `Bearer`, `JWT`, `PRIVATE KEY`). | **Dedicated regex patterns for concrete credentials**: AWS Access Keys (`AKIA...`), GitHub personal access tokens (`ghp_...`), Slack tokens (`xoxb-...`), full JSON Web Tokens, PEM private keys, and connection strings with embedded credentials (`protocol://user:pass@host`). |
| **Connection String Credentials** | Flags key names matching `database_url`, but does not inspect URIs without keyword matches. | Detects embedded credentials directly in connection URIs (`URI_CREDENTIALS`), even when configured under generic variable names. |
| **Key Name Matching Heuristics** | Unanchored substring matching on keywords (e.g. `key`, `pwd`, `token`), which can produce false positives on non-secret variables (e.g. `KEYBOARD_LAYOUT`, `PKEY_TYPE`). | Uses bounded, delimited regexes (`(?:^\|_\|-)KEYWORD(?:$\|_\|-)`) combined with non-secret suffix exclusions (`_NAME`, `_FILE`, `_PATH`, `_DIR`, `_REF`, `_TTL`, `_TIMEOUT`, etc.) and path exclusions for `PWD` / `*_PWD`. |
| **Safe Placeholders & Templates** | Requires custom configuration in `sensitiveValuesAllowed` (defaults to empty). | Automatically recognizes common placeholder values (`true`, `false`, `none`, `dummy`, `changeme`, etc.) and dynamic runtime expressions (`$(...)`, `${...}`, `{{...}}`). |
| **Configuration Files & Binary Data** | Scans ConfigMap `data` strings only. | Specifically identifies sensitive credential files (`.env`, `credentials.json`, `id_rsa`, `jwt.key`), scans both `data` and `binaryData`, and provides safe, fully redacted previews (`******`) to prevent credential leakage in responses. |

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
- **SSE Shutdown**: on the first `SIGINT` or `SIGTERM` the SSE server stops accepting connections and new tool calls (answered with `SERVER_SHUTTING_DOWN`), lets running tool calls finish for up to 20 seconds with their streams still open, then cancels what is left, closes the sessions, and exits with status 0 once the work has finished and cleanup succeeded. If tracked work has not finished by the 25-second bound, or cleanup fails, the server reports an error and the process may exit with a non-zero status. Stdio transport is unchanged.

## Related Documentation

- [Kubescape Operator Installation](https://kubescape.io/docs/operator/)
- [Vulnerability Scanning](https://kubescape.io/docs/vulnerabilities/)
- [Configuration Scanning](https://kubescape.io/docs/configuration-scanning/)
- [MCP Protocol Specification](https://modelcontextprotocol.io/)