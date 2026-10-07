# Pod Security Standards (PSS) Compliance Predictor

Kubescape includes a built-in Pod Security Standards compliance predictor available via both the CLI (`kubescape predict pss`) and the MCP server (`predict_pss_compliance` tool).

The predictor answers the fundamental hardening question:
> **"What would break if I enforced Baseline or Restricted on this namespace?"**

It allows platform engineers, security teams, and developers to assess the impact and blast radius of Pod Security Standards enforcement *before* modifying cluster admission control or applying namespace labels.

---

## What are Pod Security Standards?

The Kubernetes [Pod Security Standards (PSS)](https://kubernetes.io/docs/concepts/security/pod-security-standards/) define three cumulative security levels for pod isolation:

| Level | Purpose | Target Audience |
|-------|---------|-----------------|
| **Privileged** | Unrestricted policy, providing the widest possible level of permissions. | Administrative, infrastructure, or device-driver workloads (e.g. CNI plugins, CSI drivers). |
| **Baseline** | Minimally restrictive policy that prevents known privilege escalations with minimal configuration friction. | General workloads, business applications. |
| **Restricted** | Heavily restricted policy hardening pods against a wide range of potential bypasses and container escapes. | Security-critical applications, multi-tenant environments. |

---

## Evaluated PSS Controls (v1.37)

The predictor implements full evaluation of the Kubernetes PSS v1.37 controls:

| Category | Level | Evaluated Checks |
|----------|-------|------------------|
| **Host Namespaces** | Baseline | Disallows `hostNetwork: true`, `hostPID: true`, and `hostIPC: true`. |
| **HostProcess** | Baseline | Disallows `windowsOptions.hostProcess: true` at pod and container level. |
| **Privileged Containers** | Baseline | Disallows `privileged: true` on containers, init containers, and ephemeral containers. |
| **Capabilities** | Baseline & Restricted | **Baseline**: Disallows adding capabilities beyond the default allowed set (`AUDIT_WRITE`, `CHOWN`, `DAC_OVERRIDE`, `FOWNER`, `FSETID`, `KILL`, `MKNOD`, `NET_BIND_SERVICE`, `SETFCAP`, `SETGID`, `SETPCAP`, `SETUID`, `SYS_CHROOT`).<br>**Restricted**: Requires explicitly dropping `ALL` capabilities; only permits adding `NET_BIND_SERVICE`. (Exempted on Windows workloads). |
| **HostPath Volumes** | Baseline | Disallows `hostPath` volumes across all volume definitions. |
| **Host Ports** | Baseline | Disallows `hostPort > 0` in all container port definitions. |
| **AppArmor** | Baseline | Validates structured container `appArmorProfile` and legacy annotations (`container.apparmor.security.beta.kubernetes.io/*`). Disallows `Unconfined`. |
| **SELinux** | Baseline | Restricts `type` to standard non-privileged values (`container_t`, `container_init_t`, `container_kvm_t`, `container_engine_t`); requires `user` and `role` to be unset; disallows custom types like `spc_t`. |
| **Proc Mount** | Baseline & Restricted | Requires `procMount` to be `Default` (disallows `Unmasked`). Relaxed at Baseline for pods running in a user namespace (`hostUsers: false`) since v1.35; Restricted maintains the requirement. |
| **Sysctls** | Baseline | Only allows safe sysctls: `kernel.shm_rmid_forced`, `net.ipv4.ip_local_port_range`, `net.ipv4.ip_local_reserved_ports`, `net.ipv4.ip_unprivileged_port_start`, `net.ipv4.tcp_syncookies`, `net.ipv4.ping_group_range`, `net.ipv4.tcp_keepalive_time`, `net.ipv4.tcp_fin_timeout`, `net.ipv4.tcp_keepalive_intvl`, `net.ipv4.tcp_keepalive_probes`, `net.ipv4.tcp_rmem` (v1.32+), `net.ipv4.tcp_wmem` (v1.32+), `net.ipv4.tcp_slow_start_after_idle` (v1.37+), and `net.ipv4.tcp_notsent_lowat` (v1.37+). |
| **Host Probes & Lifecycle** | Baseline | Disallows setting `host` in `httpGet` or `tcpSocket` handlers across probes (`livenessProbe`, `readinessProbe`, `startupProbe`) and lifecycle hooks (`postStart`, `preStop`) (v1.34+). |
| **Volume Types** | Restricted | Restricts volumes to permitted types: `configMap`, `csi`, `downwardAPI`, `emptyDir`, `ephemeral`, `image`, `persistentVolumeClaim`, `projected`, `secret`. |
| **Privilege Escalation** | Restricted | Requires `allowPrivilegeEscalation: false` on all containers (exempted on Windows workloads). |
| **Running as Non-Root** | Restricted | Requires `runAsNonRoot: true` at pod or container level; disallows `runAsUser: 0` (relaxed for pods in a user namespace with `hostUsers: false` since v1.35). |
| **Seccomp** | Baseline & Restricted | **Baseline**: Any configured profile must be `RuntimeDefault` or `Localhost/*` (disallows `Unconfined`).<br>**Restricted**: Requires seccomp profile to be explicitly configured as `RuntimeDefault` or `Localhost/*` at pod or container level (exempted on Windows workloads). |

---

## CLI Usage: `kubescape predict pss`

### Basic Syntax

```bash
kubescape predict pss [<path>...] [flags]
```

### Cluster Mode

In cluster mode (no positional path arguments provided), Kubescape connects to your active Kubernetes cluster, enumerates workloads in the target namespace, and evaluates them.

```bash
# Evaluate compliance against Restricted (default level)
kubescape predict pss -n production

# Evaluate compliance against Baseline
kubescape predict pss -n staging --level Baseline

# Check a single workload before deploying changes
kubescape predict pss -n production --workload Deployment/orders-service
```

> **Automatic Deduplication**: In cluster mode, child workloads (e.g. `ReplicaSets` and `Pods` generated by `Deployments`) are automatically deduplicated so you only see root workload violations. Standalone pods and workloads created by custom CRD operators are retained as roots.

### Local Manifest Mode

Pass one or more file or directory paths to evaluate local Kubernetes manifests:

```bash
# Scan a single manifest file
kubescape predict pss ./deploy/app.yaml

# Scan all YAML/JSON manifests in a directory
kubescape predict pss ./k8s/manifests/

# Filter by workload name in local manifests
kubescape predict pss ./manifests/ --workload Deployment/web-api

# Scope local manifests to a specific namespace
kubescape predict pss ./manifests/ -n production
```

> [!NOTE]
> When scanning local manifests without `-n, --namespace`, workloads across all files are aggregated together. If identical `Kind/Name` pairs exist across different manifests/namespaces, use `-n, --namespace` to scope evaluation to a specific namespace and disambiguate resources.

---

## Output Formats

The CLI supports five output formats via the `-f, --format` flag:

| Format | Description | Primary Use Case |
|--------|-------------|------------------|
| `pretty-printer` | Rich terminal formatting with failing workload breakdown and summary | Interactive terminal review (default) |
| `table` | Tabular format listing Workload Kind, Name, Passes-At level, and Violations | Quick CLI scanning and pipeable outputs |
| `json` | Structured JSON matching the MCP predictor schema | Automation, scripting, custom dashboards |
| `sarif` | Standard Static Analysis Results Interchange Format | Repository-level GitHub Code Scanning alerts |
| `junit` | JUnit XML test suites and cases | CI/CD pipeline gating (Jenkins, GitLab CI, CircleCI) |

### Examples by Format

#### Table Format
```bash
kubescape predict pss -n production -f table
```
```
KIND        NAME           PASSES_AT   VIOLATIONS
Deployment  legacy-api     Baseline    Capabilities:main, RunAsNonRoot:main
DaemonSet   node-exporter  Privileged  HostNetwork:pod, HostPath:pod

Summary: 10/12 workloads pass at Restricted (current effective level: Privileged)
```

#### JSON Format
```bash
kubescape predict pss -n production -f json -o pss-report.json
```

#### GitHub Code Scanning (SARIF)
```bash
kubescape predict pss ./manifests/ -f sarif -o pss.sarif
```

> [!NOTE]
> SARIF output contains logical workload locations (`<namespace>/<kind>/<name>/<container>`). GitHub Code Scanning ingestion and display have not been validated. Direct inline diff annotations on Pull Requests are unsupported because this output does not include physical source file and line mappings; source locations and integration validation can be addressed in a follow-up.

#### CI/CD Test Results (JUnit)
```bash
kubescape predict pss ./manifests/ -f junit -o pss-results.xml
```

---

## Understanding the Results

### 1. Per-Workload Violations
Each failing workload details:
- **Passes At**: The strictest PSS level this workload *currently* satisfies.
- **Violations**: The specific checks that failed at the target level, indicating container name and violation description.

### 2. Current Effective Level
The **Current Effective Level** indicates the highest PSS enforcement level that can be enabled on the namespace **today** without breaking any existing workload:
- If all workloads pass Restricted: `Restricted`
- If all workloads pass Baseline but some fail Restricted: `Baseline`
- If even one workload fails Baseline: `Privileged`

### 3. Exit Codes
- `0`: All workloads were evaluated and pass at the requested target level.
- `1`: One or more workloads violate the requested target level, or the evaluation is incomplete because workloads could not be evaluated.

---

## Recommended Migration Workflows

### Workflow 1: Safely Enforce Baseline Across Namespaces
1. Run `kubescape predict pss -n <namespace> --level Baseline`.
2. If the command completes successfully with no failures or unevaluated workloads: Label the namespace for Baseline enforcement:
   ```bash
   kubectl label namespace <namespace> pod-security.kubernetes.io/enforce=baseline
   ```
3. If failures exist: Fix the offending configurations (e.g. remove `hostPath` or `privileged: true`) and re-run.

### Workflow 2: Plan Migration to Restricted
1. Run `kubescape predict pss -n <namespace> --level Restricted`.
2. Inspect the **Failing Workloads** list to identify common gaps:
   - Missing `securityContext.runAsNonRoot: true`
   - Missing `securityContext.allowPrivilegeEscalation: false`
   - Missing `capabilities.drop: ["ALL"]`
   - Missing `seccompProfile.type: RuntimeDefault`
3. Update manifests incrementally, using `kubescape predict pss ./manifests/` in pull requests to verify compliance.

### Workflow 3: CI/CD Pull Request Gate
Add PSS prediction to your CI pipeline to prevent non-compliant workloads from ever merging:

```yaml
- name: Predict PSS Compliance
  run: |
    kubescape predict pss ./kubernetes/ --level Baseline -f junit -o pss-results.xml
```

---

## CLI vs. MCP Predictor

| Capability | CLI (`kubescape predict pss`) | MCP Tool (`predict_pss_compliance`) |
|------------|--------------------------------|--------------------------------------|
| **Interface** | Terminal / Shell / CI/CD scripts | AI Assistant prompt (Claude, ChatGPT) |
| **Local Manifests** | Supported (`kubescape predict pss ./path`) | Cluster only (reads via dynamic client) |
| **Output Formats** | Pretty, Table, JSON, SARIF, JUnit | JSON text payload for AI reasoning |
| **Automation** | Direct integration into GitOps & GitHub Actions | Conversational hardening planning & audit |
