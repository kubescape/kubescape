---
name: kubescape-fix
description: Remediate Kubescape posture findings with kubescape fix against a prior JSON scan report. Use to preview or apply in-place manifest fixes, write copies/patches/Kustomize overlays, narrow by control ID, and optionally verify remediations.
license: Apache-2.0
compatibility: Requires the kubescape CLI on PATH and a JSON report from a prior kubescape scan of local manifests or a cluster.
metadata:
  author: kubescape
  version: "0.1.0"
---

# Kubescape fix

`kubescape fix` remediates misconfigurations recorded in a scan report. It does not invent changes without that report.

## Workflow

```bash
# 1) Scan local files to JSON
kubescape scan ./manifests -f json -o results.json

# 2) Preview
kubescape fix results.json --dry-run

# 3) Apply (interactive confirm on a TTY; use --no-confirm in CI)
kubescape fix results.json
kubescape fix results.json --no-confirm
```

Cluster scans have no local files to rewrite: fixes print to stdout for review/apply (or use `--output-dir`).

```bash
kubescape scan -f json -o cluster.json
kubescape fix cluster.json | kubectl apply -f -
kubescape fix cluster.json --output-dir ./fixes
```

## Safe output modes

Prefer non-destructive modes when reviewing:

```bash
# Fixed copies (tree layout mirrors the scan roots)
kubescape fix results.json --output-dir ./fixed

# Unified diff to review / git apply
kubescape fix results.json --output-patch remediation.patch

# Helm-rendered resources: Kustomize JSON 6902 overlay
kubescape fix results.json --output-kustomize ./patches --values ./my-chart/values.yaml
```

Helm chart sources are not edited in place; use `--output-kustomize` for machine-applicable patches. Match scan-time Helm values with `--values` / `-f`, `--set`, `--set-string`, `--set-file`, `--release-name`, `--release-namespace`.

## Narrow which controls are fixed

```bash
kubescape fix results.json --no-confirm --include-controls C-0016,C-0017
kubescape fix results.json --no-confirm --skip-controls C-0055
```

Matching is case-insensitive on control ID; `--skip-controls` wins if both lists mention the same control.

## Verify

```bash
kubescape fix results.json --no-confirm --verify
```

Re-scans after applying to check that selected remediations cleared their findings.

## Important behaviors

- YAML keeps comments/layout for in-place edits; JSON is re-encoded at existing indentation.
- `kind: List` wrappers are left alone; multi-document YAML is fixed per document.
- Identity must still match the report (apiVersion/kind/namespace/name); otherwise the file is skipped — re-scan first.
- Non-interactive stdin (no TTY) skips the confirm prompt and applies nothing unless `--no-confirm`.
- `--output-dir`, `--output-patch`, and cluster stdout modes do not use the in-place confirm prompt; `--output-kustomize` may still prompt before overwriting an existing overlay unless `--no-confirm`.

## Agent checklist

1. Always start from a fresh `-f json` report of the same tree you will fix.
2. Prefer `--dry-run`, `--output-dir`, or `--output-patch` before in-place `--no-confirm`.
3. Do not claim image CVE patching here — that is `kubescape patch` (separate command), not `kubescape fix`.
4. See `docs/cli-reference.md` (`kubescape fix`) for full flag behavior.
