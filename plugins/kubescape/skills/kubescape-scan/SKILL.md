---
name: kubescape-scan
description: Run Kubescape CLI scans on Kubernetes clusters, YAML/JSON manifests, Helm charts, Kustomize dirs, git URLs, and container images. Use for NSA/MITRE/CIS and other frameworks, controls, severity gates, and report formats (json, sarif, junit, html, etc.).
license: Apache-2.0
compatibility: Requires the kubescape CLI on PATH (v3+ recommended) and cluster/kubeconfig access for live scans.
metadata:
  author: kubescape
  version: "0.1.0"
---

# Kubescape scan

Use the `kubescape` CLI. Prefer documented subcommands and flags; do not invent options.

## Prerequisites

- `kubescape` installed and on `PATH` (`kubescape version` to confirm).
- Live cluster scans need a usable kubeconfig (`--kubeconfig`, `--kube-context` as needed).
- Offline/air-gapped: load policies with `--use-from` / `--use-artifacts-from` / `--use-default` as documented in the repo docs.

## Targets

```bash
# Current cluster (default frameworks include clusterscan, mitre, nsa)
kubescape scan

# Local manifests, Helm chart, or Kustomize directory
kubescape scan ./manifests
kubescape scan ./charts/my-chart
kubescape scan ./kustomize/overlays/prod

# Git repository URL
kubescape scan https://github.com/example/k8s-manifests

# Stdin
cat deployment.yaml | kubescape scan -
```

Helm rendering supports `--values`, `--set`, `--set-string`, `--set-file`, `--release-name`, `--release-namespace`, `--kube-version`, and `--api-versions` (same idea as `helm template`). Charts are scanned as a new install (`.Release.IsInstall` true).

## Frameworks and controls

List what is available before guessing names:

```bash
kubescape list frameworks
kubescape list controls
kubescape list controls --framework nsa
```

Common frameworks (names are case-insensitive; CIS uses a versioned id):

| Name | Meaning |
|------|---------|
| `nsa` | NSA-CISA Kubernetes Hardening Guidance |
| `mitre` | MITRE ATT&CK for Kubernetes |
| `cis-v1.23-t1.0.1` | CIS Kubernetes Benchmark |
| `soc2`, `pci-dss`, `hipaa` | Compliance frameworks |

```bash
kubescape scan framework nsa
kubescape scan framework mitre --include-namespaces production
kubescape scan framework cis-v1.23-t1.0.1 ./manifests
kubescape scan framework nsa,mitre

# Single control by ID, name, or CIS section when present
kubescape scan control C-0057 -v
kubescape scan control "privileged container" -v
kubescape scan control CIS-5.2.1
```

Useful scope flags: `--include-namespaces` / `-e --exclude-namespaces`, `--include-kinds` / `--exclude-kinds`, `--label-selector`, `--include-controls` / `--skip-controls` / `--exclude-controls`, `--host-scan` (or `--host-scan=false`).

## Images

```bash
kubescape scan image nginx:1.27
kubescape scan image nginx:1.27 redis:7 --platform linux/amd64

# Private registry: prefer env vars so the password is not on argv
export KUBESCAPE_REGISTRY_USERNAME="$USER"
export KUBESCAPE_REGISTRY_PASSWORD="$PASS"
kubescape scan image myregistry.io/app:tag

# Posture scan that also analyzes workload images
kubescape scan --scan-images
kubescape scan ./manifests --scan-images --format cyclonedx-json --output sbom
```

Image risk gates (need an image scan or `--scan-images`): `--severity-threshold`, `--fail-on-kev`, `--epss-threshold`, `--only-fixable`, `--skip-db-update`, `--max-db-age`, `--fail-on-stale-db`.

## Output formats and views

`-f` / `--format` (comma-separated for multiple). Common posture values: `pretty-printer` (default), `json`, `junit`, `sarif`, `html`, `pdf`, `prometheus`, `yaml`, `csv`, `markdown`, `policyreport`, `exceptions`, `github-actions`, GitLab formats, plus `cyclonedx-json` / `spdx-json` with `--scan-images`.

```bash
kubescape scan framework nsa -f json -o results.json
kubescape scan ./manifests -f sarif -o results.sarif
kubescape scan ./manifests -f json,exceptions -o scan-result
kubescape scan framework nsa --view control -E   # evidence paths (pretty-printer)
kubescape scan framework nsa --compliance-threshold 80
kubescape scan --min-severity high --severity-threshold high
```

`--output` / `-o` writes the report. `--verbose` / `-v` shows all resources, not only failed ones.

## Workloads

```bash
kubescape scan workload Deployment/nginx
kubescape scan workload staging/Deployment/nginx
kubescape scan workload Deployment/nginx ./manifests
```

Kind is required (e.g. `Deployment`, not plural `deployments`). Namespace in the arg and `-n` / `--namespace` must agree if both are set.

## Agent checklist

1. Confirm `kubescape` is available; install from project docs if missing.
2. Prefer `kubescape list frameworks` / `list controls` over inventing names.
3. For CI or follow-up `kubescape fix`, write `-f json -o <file>`.
4. Keep secrets out of argv when possible (registry creds also accept env vars documented in the CLI reference).
5. For full flag lists, read `docs/cli-reference.md` and `docs/getting-started.md` in this repository.
