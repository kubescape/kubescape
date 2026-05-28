# Go Version and GOMEMLIMIT Audit

> **Issue:** [#2280](https://github.com/kubescape/kubescape/issues/2280) — Add a newcomer-friendly audit document tracing where Go version pins and GOMEMLIMIT are set.

This document maps every place Go version and `GOMEMLIMIT` are configured across the kubescape repo and its sibling helm-charts repo, so contributors know exactly where to update when either changes.

---

## Go Version Pins

### 1. `go.mod` — Root module

```
go 1.25.10
```

The `go` directive in the root `go.mod` is the canonical version declaration. All other Go pins must be kept in sync with this value.

**File:** `go.mod` (line 2)

---

### 2. `httphandler/go.mod` — HTTP handler submodule

```
go 1.25.10
```

The `httphandler/` sub-module carries its own `go` directive (which must match the root).

**File:** `httphandler/go.mod` (line 2)

---

### 3. `.github/workflows/02-release.yaml` — Release workflow Go setup

```yaml
- uses: actions/setup-go@40f1582b2485089dde7abd97c1529aa768e1baff # v5.6.0
  with:
    go-version: "1.25"
```

The release workflow pins to `"1.25"` (minor-only, not patch-level). The action uses [GitHub's pinned action SHA](https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions#using-third-party-actions) for supply-chain security.

**Note:** This uses `go-version: "1.25"` rather than `go-version-file: go.mod`, meaning it does **not** auto-follow the `go.mod` directive. When the `go` directive advances to 1.26, this workflow needs to be updated manually.

**File:** `.github/workflows/02-release.yaml`

---

### 4. `.github/workflows/a-pr-scanner.yaml` — Reusable PR scanner workflow

```yaml
- uses: actions/setup-go@7b8cf10d4e4a01d4992d18a89f4d7dc5a3e6d6f4 # v4.3.0
  name: Installing go
  with:
    go-version-file: go.mod
```

Unlike the release workflow, this reusable workflow reads the version directly from `go.mod` via `go-version-file`. This means it stays in sync automatically — when `go.mod` is updated, this workflow picks up the new version without any manual change.

**File:** `.github/workflows/a-pr-scanner.yaml`

---

### 5. `build/README.md` — Documentation Go requirement

```
### Required
- **Go 1.23+** - [Installation Guide](https://golang.org/doc/install)
```

The build README states a minimum of Go 1.23, which is **behind** the actual `go 1.25.10` directive. This discrepancy should be resolved: update `build/README.md` to reflect the current minimum (`go 1.25.10` → document as `Go 1.25+`).

**File:** `build/README.md`

---

## Summary: Go Version Pin Locations

| Location | Pin Style | Auto-syncs with go.mod? |
|---|---|---|
| `go.mod` | `go 1.25.10` | — (source of truth) |
| `httphandler/go.mod` | `go 1.25.10` | Manual |
| `.github/workflows/02-release.yaml` | `go-version: "1.25"` | No |
| `.github/workflows/a-pr-scanner.yaml` | `go-version-file: go.mod` | Yes |
| `build/README.md` | `Go 1.23+` (docs) | No (out of date) |

---

## GOMEMLIMIT Configuration

`GOMEMLIMIT` is set in the helm-charts repository's Kubernetes deployment templates. The value is calculated as a percentage of the container's memory limit via a shared Helm template function.

### Template function definition

The `kubescape-operator.gomemlimit` template function multiplies the container memory limit by a configurable percentage:

```
value: {{ include "kubescape-operator.gomemlimit" (dict "memory" .Values.<component>.resources.limits.memory "percentage" .Values.<component>.gomemlimitPercentage) | quote }}
```

### Default percentage

In `charts/kubescape-operator/values.yaml`:

```yaml
# node-agent
gomemlimitPercentage: 0.8   # 80% of resources.limits.memory

# kubevuln
gomemlimitPercentage: 0.8   # 80% of resources.limits.memory
```

### Where GOMEMLIMIT is set (helm-charts repo)

| Component | File | Notes |
|---|---|---|
| `kubevuln` | `charts/kubescape-operator/templates/kubevuln/deployment.yaml` | Two containers: main + sbom-scanner |
| `node-agent` | `charts/kubescape-operator/templates/synchronizer/deployment.yaml` | |
| `operator` | `charts/kubescape-operator/templates/operator/deployment.yaml` | |
| `storage` | `charts/kubescape-operator/templates/storage/deployment.yaml` | |
| `prometheus-exporter` | `charts/kubescape-operator/templates/prometheus-exporter/deployment.yaml` | |
| `kubescape` | `charts/kubescape-operator/templates/kubescape/deployment.yaml` | |

### Example rendered value (from snapshot tests)

For `node-agent` with default memory limit and 80%:

```yaml
- name: GOMEMLIMIT
  value: "{{ .GoMemLimit }}"   # rendered as e.g. "3276MiB" at 80% of 4Gi limit
```

**Source repo:** https://github.com/kubescape/helm-charts

---

## Evidence Appendix A — kubescape Repository

### A.1 Root go.mod

```
module github.com/kubescape/kubescape/v3

go 1.25.10
```

### A.2 httphandler/go.mod

```
module github.com/kubescape/kubescape/v3/httphandler

go 1.25.10

replace github.com/kubescape/kubescape/v3 => ../
```

### A.3 `.github/workflows/02-release.yaml` (relevant excerpt)

```yaml
      - uses: actions/setup-go@40f1582b2485089dde7abd97c1529aa768e1baff # v5.6.0
        with:
          go-version: "1.25"
```

### A.4 `.github/workflows/a-pr-scanner.yaml` (relevant excerpt)

```yaml
      - uses: actions/setup-go@7b8cf10d4e4a01d4992d18a89f4d7dc5a3e6d6f4 # v4.3.0
        name: Installing go
        with:
          go-version-file: go.mod
```

### A.5 `build/README.md` (relevant excerpt)

```markdown
### Required
- **Go 1.23+** - [Installation Guide](https://golang.org/doc/install)
```

---

## Evidence Appendix B — helm-charts Repository

### B.1 `charts/kubescape-operator/values.yaml` (relevant excerpt)

```yaml
nodeAgent:
  gomemlimitPercentage: 0.8

kubevuln:
  gomemlimitPercentage: 0.8
```

### B.2 Template usage example — node-agent DaemonSet

```yaml
# charts/kubescape-operator/templates/synchronizer/deployment.yaml
env:
  - name: GOMEMLIMIT
    value: {{ include "kubescape-operator.gomemlimit" (dict "memory" .Values.synchronizer.resources.limits.memory "percentage" .Values.synchronizer.gomemlimitPercentage) | quote }}
```

### B.3 Rendered snapshot (node-agent, 4Gi memory limit, 80%)

```yaml
- name: GOMEMLIMIT
  value: "3276MiB"
```

---

## Action Items for Contributors

1. **When bumping the Go version in `go.mod`:**
   - [ ] Update `go 1.xx` in `go.mod` (root)
   - [ ] Update `go 1.xx` in `httphandler/go.mod`
   - [ ] Update `go-version: "1.xx"` in `.github/workflows/02-release.yaml`
   - [ ] Update `Go 1.xx+` in `build/README.md`
   - Note: `a-pr-scanner.yaml` auto-syncs via `go-version-file: go.mod`

2. **When adjusting GOMEMLIMIT:**
   - [ ] Update `gomemlimitPercentage` in `charts/kubescape-operator/values.yaml` (for each component)
   - [ ] Rebuild and update snapshot tests in `charts/kubescape-operator/tests/__snapshot__/`

---

*Generated for issue [#2280](https://github.com/kubescape/kubescape/issues/2280).*