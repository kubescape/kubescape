# Kubescape MCP Server

The Kubescape MCP (Model Context Protocol) Server enables AI assistants to query your Kubernetes cluster's security posture using natural language. It exposes Kubescape's vulnerability and configuration scan data through the [MCP protocol](https://modelcontextprotocol.io/).

## Overview

The MCP server allows AI assistants (like Claude, ChatGPT, or custom AI tools) to:

- List and query vulnerability manifests for images and workloads
- Retrieve CVE details and vulnerability matches
- Look up the packages in image SBOMs
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

To serve clients over HTTP instead, use the SSE transport. It listens on `127.0.0.1` only, on port 8080 unless `--port` says otherwise, and answers `403` to a request whose `Origin` header names another site. Clients that send no `Origin`, such as CLIs, are unaffected:

```bash
kubescape mcpserver --transport sse --port 8080
```

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

List the vulnerabilities (CVEs) found in a specific manifest: one entry per CVE and affected package, most severe first. Results come in pages; long text fields are only included with `include_details`. The full records stay available through the `kubescape://vulnerability-manifests/{namespace}/{manifest_name}` resource.

**Parameters:**
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `namespace` | string | No | Namespace of the manifest (default: `"kubescape"`) |
| `manifest_name` | string | Yes | Name of the manifest |
| `min_severity` | string | No | Minimum severity: `Critical`, `High`, `Medium`, `Low` or `Negligible` (default: every severity) |
| `fixable_only` | boolean | No | Only vulnerabilities with a fixed version (default: `false`) |
| `include_details` | boolean | No | Add `description`, `cvss`, `urls`, `advisories` and `data_source` to each entry (default: `false`) |
| `limit` | number | No | Entries per page, 1–500 (default: `100`) |
| `offset` | number | No | Entries to skip; pass the previous `next_offset` (default: `0`) |

**Example Response:**
```json
{
  "total": 48,
  "returned": 2,
  "truncated": true,
  "next_offset": 2,
  "vulnerabilities": [
    {
      "id": "CVE-2021-22945",
      "severity": "Critical",
      "package": "curl",
      "version": "7.74.0-1.3+deb11u1",
      "package_type": "deb",
      "fix": {"versions": ["7.74.0-1.3+deb11u2"], "state": "fixed"}
    },
    {
      "id": "CVE-2021-22945",
      "severity": "Critical",
      "package": "libcurl4",
      "version": "7.74.0-1.3+deb11u1",
      "package_type": "deb",
      "fix": {"versions": ["7.74.0-1.3+deb11u2"], "state": "fixed"}
    }
  ]
}
```

#### `list_vulnerability_matches_for_cve`

Get detailed information about a specific CVE in a manifest, including affected packages and fix information.

**Parameters:**
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `namespace` | string | No | Namespace of the manifest (default: `"kubescape"`) |
| `manifest_name` | string | Yes | Name of the manifest |
| `cve_id` | string | Yes | CVE identifier (e.g., `"CVE-2023-12345"`) |

#### `analyze_vulnerability_exposure`

Correlate known image vulnerabilities (from already-scanned `VulnerabilityManifest` objects) with how reachable each workload is: its NetworkPolicy ingress exposure and its external exposure through a Service, Ingress, or Gateway API route. With `include_identity` it also reports the ServiceAccount each vulnerable workload runs as and what the existing RBAC escalation analysis finds for it.

**Parameters:**
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `namespace` | string | No | Restrict to one namespace (default: cluster-wide) |
| `min_severity` | string | No | Minimum severity: `Critical`, `High` (default), `Medium`, `Low`, `Negligible` |
| `include_identity` | boolean | No | Add the `identity` section described below (default `false`) |

When `include_identity` is omitted, `null`, or `false`, the response is exactly what it was before the option existed: `findings` and, if there are any, `warnings`. A value that is not a boolean returns an `INVALID_ARGUMENT` error.

##### Identity context (`include_identity: true`)

The response gains two keys; `findings` is unchanged and no severity is altered.

- `identity`: one entry per workload that has at least one vulnerability at or above `min_severity`, sorted by namespace, kind, and name. Workloads are matched by their exact namespace, kind, and name from the manifest's workload ID, never by name alone.
- `identity_note`: a reminder of the limits described below.

Each entry has:

| Field | Meaning |
|-------|---------|
| `namespace`, `workload_kind`, `workload_name` | The workload |
| `vulnerabilities` | Its vulnerabilities at or above `min_severity` (`cve_id`, `severity`, `fix_available`), de-duplicated by CVE ID, keeping the highest severity any copy reports |
| `status` | See [Statuses](#statuses) |
| `reason` | Why the status is not `analyzed` (when applicable) |
| `service_account` | `namespace`, `name`, `origin` (`explicit`, `defaulted`, or `unknown`), and `object_collected` (`present`, `absent`, or `unknown`). Absent when the workload could not be resolved |
| `token` | `state` (`mounted`, `not-mounted`, or `unknown`) and a `reason` for the last two |
| `rbac` | `state`: `complete`, `partial`, or `unavailable` |
| `permissions` | The RBAC analysis of the ServiceAccount, described below. Present only when the analysis ran |

###### Statuses

| Status | Meaning | What it does not mean |
|--------|---------|-----------------------|
| `analyzed` | The workload resolved to a ServiceAccount, RBAC objects were collected completely, and the escalation analysis ran | That the ServiceAccount is safe, or that it gains no permissions |
| `token-not-mounted` | As `analyzed`, but the workload spec shows no ServiceAccount token reaching the pod. The RBAC analysis is still included | That the ServiceAccount's permissions are irrelevant |
| `workload-unresolved` | No ServiceAccount could be established (unsupported kind, object not found, an unreadable spec, or a static/mirror Pod, which the kubelet creates without a ServiceAccount). `reason` says why | Anything about the workload's identity or RBAC |
| `rbac-unavailable` | RBAC objects could not be listed, so no analysis ran | An empty analysis |
| `rbac-incomplete` | Some RBAC objects could not be decoded. The analysis covers only what was collected, and it is included | A complete analysis |

###### Direct and gained permissions

`permissions` keeps these separate, and none implies another:

| Field | Meaning |
|-------|---------|
| `direct_rules` | Rules the ServiceAccount holds through its own bindings, including bindings to the implicit groups `system:serviceaccounts`, `system:serviceaccounts:<namespace>`, and `system:authenticated` |
| `gained_rules`, `permission_gain` | The analysis's effective rules that are not direct rules. They can come from a finite `bind` or `escalate` grant, from the rules of an identity the ServiceAccount can reach (`identities_reached`), or from a wildcard rule the analysis derives from a namespace-scoped `unbounded` finding. A finite gain can appear while `identities_reached` and `unbounded` are empty and `cluster_admin` is false |
| `grants` | The finite `bind` and `escalate` grants the analysis applied: the subject that adopted each (the ServiceAccount itself, or an identity it can reach), the primitive (`bind-verb` or `escalate-verb`), the scope, and the target Role or ClusterRole. It does not explain every entry in `gained_rules`: a rule inherited from a reached identity, or a wildcard derived from an `unbounded` finding, has no entry here, so an empty `grants` is not evidence that `gained_rules` is empty |
| `identities_reached` | Other identities it can assume (impersonation, creating a pod as another ServiceAccount, minting a token), each with its path |
| `unbounded` | Grants that cannot be enumerated (for example an unrestricted `bind`), with their scope. An entry with `scope_unknown: true` is a warning about a Role that could not be found and grants nothing |
| `scope_unknown` | Whether any `unbounded` entry has an unresolved scope |
| `cluster_admin` | Whether cluster-admin-equivalent power is reachable by RBAC alone. When true, `gained_rules` and `identities_reached` are not complete enumerations |
| `truncated` | The search ran out of budget before reaching a verdict, so a missing path is not confirmed |
| `no_additional_reachability_found` | True only when RBAC was collected completely, the search was not truncated, and no other identity, unbounded grant, or unknown scope was found. It is not "safe" and says nothing about `gained_rules` |

###### Token states

The token state is the workload spec's static assessment of whether a ServiceAccount token reaches the pod. It is reported separately and never changes the RBAC analysis.

- `mounted`: the ServiceAccount admission plugin would inject a token (automounting is on and some container does not already mount something at `/var/run/secrets/kubernetes.io/serviceaccount`), or a container mounts a projected `serviceAccountToken` volume in a way that exposes the token file. A `subPath` exposes it when it is `.`, the token file, or a directory containing it, after path cleaning (`./token` is the token file); a sibling file does not.
- `not-mounted`: every such route is closed in the spec. It does not rule out a token mounted from a long-lived token Secret volume, which is not modelled.
- `unknown`: the spec cannot establish it, for example the ServiceAccount's own `automountServiceAccountToken` is unset and the ServiceAccount object was not collected, a `subPathExpr` refers to environment variables (`$(VAR)`), or part of the spec could not be read. `unknown` is never reported as `not-mounted`.

Kubernetes has no namespace-level automount setting; the pod spec's `automountServiceAccountToken` takes precedence over the ServiceAccount's, which defaults to true.

The assessment is made from the workload object as it is stored. For a controller it describes the pod template, not individual running Pods, and it does not model mutating admission webhooks or other controllers that change a pod after creation, tokens mounted from a long-lived token Secret, or processes that obtain a token another way. Ephemeral containers are considered only for mounting a token volume the pod already has.

###### Limits

- The identity section is static context. It does not establish that a vulnerability is exploitable, that a credential is usable, that admission control (Pod Security, Kyverno, Gatekeeper) would allow a step, or what the workload does at runtime.
- A missing, unresolved, incomplete, or truncated result is not evidence of safety.
- RBAC objects are always collected cluster-wide, whatever `namespace` is set to, because an escalation path can lead into any namespace. If they cannot be listed, the workloads are reported `rbac-unavailable` and the rest of the response is unaffected.
- The ServiceAccount is read from the live workload object: the pod spec for a Pod, or the pod template for Deployment, StatefulSet, DaemonSet, ReplicaSet, Job, and CronJob. Other kinds are `workload-unresolved`.
- Vulnerabilities are attributed per workload from the manifest's workload ID, so an image-level manifest without one is not included.
- The workload objects and the RBAC objects are read by separate API calls, so they can reflect slightly different moments in a changing cluster.

**Example (abridged):**
```json
{
  "findings": [ ... ],
  "identity": [
    {
      "namespace": "prod",
      "workload_kind": "Deployment",
      "workload_name": "api",
      "status": "analyzed",
      "vulnerabilities": [{"cve_id": "CVE-2024-1", "severity": "Critical", "fix_available": false}],
      "service_account": {"namespace": "prod", "name": "api", "origin": "explicit", "object_collected": "present"},
      "token": {"state": "mounted"},
      "rbac": {"state": "complete"},
      "permissions": {
        "direct_rules": [ ... ],
        "gained_rules": [{"scope": "prod", "api_groups": [""], "resources": ["secrets"], "verbs": ["get", "list"]}],
        "permission_gain": true,
        "grants": [{"subject": "ServiceAccount prod/api", "primitive": "bind-verb", "scope": "prod", "detail": "...", "target": {"kind": "Role", "namespace": "prod", "name": "secret-reader"}}],
        "identities_reached": [],
        "unbounded": [],
        "scope_unknown": false,
        "cluster_admin": false,
        "truncated": false,
        "no_additional_reachability_found": true
      }
    }
  ],
  "identity_note": "..."
}
```

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

Get detailed configuration scan results for a specific workload, including failed controls and remediation guidance. Most controls in a result usually passed, so use `status: "failed"` to get only the ones that need fixing. Without filters every control is returned.

**Parameters:**
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `namespace` | string | No | Namespace of the manifest (default: `"kubescape"`) |
| `manifest_name` | string | Yes | Name of the configuration manifest |
| `status` | string | No | Only controls with these statuses, comma-separated: `failed`, `passed`, `skipped` |
| `min_severity` | string | No | Only controls at or above this severity: `Critical`, `High`, `Medium` or `Low` |

### Policy Tools

#### `list_frameworks`

List the names of the frameworks available for scanning (for example `NSA`, `MITRE`, `cis-v1.12.0`).

#### `list_controls`

List the security controls with their IDs, names and the frameworks they belong to. Use `framework` to get one framework's controls instead of all of them (about 290).

**Parameters:**
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `framework` | string | No | Only controls of this framework, case-insensitive (see `list_frameworks`). An unknown name returns an error listing the valid ones |

**Example Response** (`framework: "NSA"`):
```json
[
  {"id": "C-0002", "name": "Prevent containers from allowing command execution", "frameworks": ["MITRE", "ArmoBest", "NSA", "AllControls", "ClusterScan"]},
  {"id": "C-0005", "name": "API server insecure port is enabled", "frameworks": ["ArmoBest", "NSA", "AllControls", "ClusterScan", "security"]}
]
```

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

### Admission Policy Tools

Both tools read only the CEL admission policy library embedded in the Kubescape binary. They make no cluster, file or network access, and neither applies anything to a cluster. Kubescape's ValidatingAdmissionPolicy support is experimental.

#### `list_admission_policies`

List the ValidatingAdmissionPolicies in the embedded library, with the Kubescape control each one implements (`controlID`), whether it reads parameters (`takesParams`), its `failurePolicy` and the `resources` it matches. It takes no arguments. The output is the same as `kubescape vap list-policies --format json`.

#### `create_admission_policy_binding`

Generate a `ValidatingAdmissionPolicyBinding` manifest. The tool runs the same validation as `kubescape vap create-policy-binding` and returns the YAML for you to review; it does **not** apply it to a cluster. Pipe the `manifest` to `kubectl apply -f -` yourself once you are happy with it.

**Arguments:**

| Argument | Type | Description |
|----------|------|-------------|
| `binding_name` | string, required | Name of the binding (a DNS-1123 subdomain) |
| `policy_name` | string | Name of the policy to bind. Exactly one of `policy_name` or `control_id` is required |
| `control_id` | string | Kubescape control ID whose policy to bind, in any casing (e.g. `C-0016`) |
| `validation_actions` | string array | `Deny`, `Warn` and/or `Audit`. `Deny` and `Warn` cannot be combined. Default: `["Deny"]` |
| `parameter_reference` | string | Name of the object the policy reads as params. Required for a policy that declares a `paramKind`, rejected for one that declares none |
| `namespaces` | string array | Narrow the binding to these namespaces. Only namespaced resources are narrowed |
| `labels` | string array | Object label selector, as `key=value` or `key==value` |
| `resource_rules` | string array | Restrict the binding to `group/version/resource` entries the policy already matches, e.g. `apps/v1/deployments` or `/v1/pods` |

**Response:**

```json
{
  "policy": "kubescape-c-0016-allow-privilege-escalation",
  "controlID": "C-0016",
  "manifest": "apiVersion: admissionregistration.k8s.io/v1\nkind: ValidatingAdmissionPolicyBinding\n...",
  "warnings": []
}
```

- `policy` is the resolved policy name; `controlID` is present only when the binding was requested by control.
- `manifest` is the generated YAML. The same inputs always produce the same manifest.
- `warnings` is always an array. It lists scope findings that do not block the binding, such as a `namespaces` selector on a policy that matches both namespaced and cluster-scoped resources (the selector narrows only the namespaced ones, and the binding still applies to the matching cluster-scoped resources cluster-wide), or a resource rule that names another API group or version than the policy constrains.

A policy name that is not in the embedded library is accepted as is; its parameter and scope checks are skipped, as in the CLI.

**Errors:** `INVALID_ARGUMENT` for any rejected input: a missing `binding_name`; neither or both of `policy_name` and `control_id`; an unknown control ID; an invalid binding name or namespace; a repeated action or `Deny` combined with `Warn`; a malformed label or resource rule; a resource rule outside the policy's match constraints; `namespaces` that narrow nothing because every covered resource is cluster-scoped; a missing `parameter_reference` for a policy with a `paramKind` (the message names the required kind); or a `parameter_reference` for a policy that takes none. Messages are the CLI's, so they may refer to the matching flag, for example `--parameter-reference`. `MARSHAL_ERROR` if the manifest or the response cannot be serialized.

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

### SBOM Tools

#### `list_sboms`

List the image SBOMs stored in the cluster, without their content.

**Parameters:**
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `namespace` | string | No | Namespace to list (default: all namespaces) |
| `continue` | string | No | Continuation token from the previous response |

**Example Response:**
```json
{
  "sboms": [
    {
      "namespace": "kubescape",
      "sbom_name": "docker.io-library-nginx-1.21-65e514",
      "image_id": "docker.io/library/nginx@sha256:2bcabc23b45489fb0885d69a06ba1d648aeda973fae7bb981bafbb884165e514",
      "image_tag": "docker.io/library/nginx:1.21",
      "status": "ready"
    }
  ]
}
```

#### `list_sbom_packages`

List the packages in an SBOM, sorted by name. File locations, CPEs and cataloger metadata are left out; the same package found in several places is listed once. `status` is the SBOM's status in storage: an SBOM that was too large to store has no packages.

**Parameters:**
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `namespace` | string | No | Namespace of the SBOM (default: `"kubescape"`) |
| `sbom_name` | string | Yes | Name of the SBOM (see `list_sboms`) |
| `name` | string | No | Only packages whose name contains this text, case-insensitive |
| `package_type` | string | No | Only packages of this type, e.g. `deb`, `rpm`, `apk`, `npm`, `python`, `go-module`, `java-archive` |
| `limit` | number | No | Maximum number of packages to return (default 100, max 500) |
| `offset` | number | No | Number of packages to skip; use `next_offset` from the previous response |

**Example Response** (`name: "ssl"`):
```json
{
  "sbom_name": "docker.io-library-nginx-1.21-65e514",
  "status": "ready",
  "distro": "debian 11",
  "total": 2,
  "returned": 2,
  "truncated": false,
  "packages": [
    {"name": "libssl1.1", "version": "1.1.1n-0+deb11u2", "type": "deb", "purl": "pkg:deb/debian/libssl1.1@1.1.1n-0%2Bdeb11u2?arch=amd64&distro=debian-11&upstream=openssl", "licenses": ["OpenSSL"]},
    {"name": "openssl", "version": "1.1.1n-0+deb11u2", "type": "deb", "purl": "pkg:deb/debian/openssl@1.1.1n-0%2Bdeb11u2?arch=amd64&distro=debian-11", "licenses": ["OpenSSL"]}
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
- **SSE Shutdown**: on the first `SIGINT` or `SIGTERM` the SSE server stops accepting connections and new tool calls (answered with `SERVER_SHUTTING_DOWN`), lets running tool calls finish for up to 20 seconds with their streams still open, then cancels what is left, closes the sessions, and exits with status 0 once the work has finished and cleanup succeeded. If tracked work has not finished by the 25-second bound, or cleanup fails, the server reports an error and the process may exit with a non-zero status. Stdio transport is unchanged.

## Related Documentation

- [Kubescape Operator Installation](https://kubescape.io/docs/operator/)
- [Vulnerability Scanning](https://kubescape.io/docs/vulnerabilities/)
- [Configuration Scanning](https://kubescape.io/docs/configuration-scanning/)
- [MCP Protocol Specification](https://modelcontextprotocol.io/)