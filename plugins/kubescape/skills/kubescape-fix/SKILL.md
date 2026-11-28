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

# 3) Apply (interactive confirm on a TTY)
kubescape fix results.json
```

CI / non-interactive (skips the confirm prompt):

```bash
kubescape fix results.json --no-confirm
```

Cluster scans have no local files to rewrite: write fixes to a file (or `--output-dir`) for review, then apply only after the user authorizes that action.

```bash
kubescape scan -f json -o cluster.json
kubescape fix cluster.json --output-dir ./fixes
# Or: kubescape fix cluster.json > fixes.yaml
# Review the written manifests, then only if the user authorizes:
# kubectl apply -f ./fixes   # or: kubectl apply -f fixes.yaml
```

## Safe output modes

Prefer non-destructive modes when reviewing without changing originals: fixed copies or a unified diff. In-place fix rewrites the original manifests — do not use it when the user asked for review without changes.

```bash
# Fixed copies (tree layout mirrors the scan roots)
kubescape fix results.json --output-dir ./fixed

# Unified diff to review / git apply
kubescape fix results.json --output-patch remediation.patch
```

`--output-kustomize` writes patches only for Helm-rendered resources, and only from a report produced by scanning a Helm chart. A plain-manifest report (for example from `./manifests`) yields no overlay. Scan the chart, then pass that report:

```bash
kubescape scan ./my-chart -f json -o chart-results.json
kubescape fix chart-results.json --output-kustomize ./patches --values ./my-chart/values.yaml
```

A mixed report (Helm-rendered resources plus plain manifests) is not fully safe under `--output-kustomize` alone: the overlay is written first, then `fix` continues to the in-place path for plain manifests (guarded by the confirmation prompt; with `--no-confirm` or after confirm, those originals change). When originals must stay unchanged, scan the chart alone for `--output-kustomize`, and handle plain manifests in a separate run with `--output-dir` or `--output-patch`.

Helm chart sources are not edited in place; use `--output-kustomize` for machine-applicable patches on eligible Helm-rendered resources. Match scan-time Helm values with `--values` / `-f`, `--set`, `--set-string`, `--set-file`, `--release-name`, `--release-namespace`.

In `--output-kustomize` mode, `fix` declines container workloads from an ordinary scan report: the report redacts container environment configuration and does not supply scan-time provenance. Non-container resources such as Services are still emitted, and each declined resource is listed with its reason.

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

Re-scans after applying to check that selected remediations cleared their findings. The rescan uses the controls configuration the report records (or `--controls-config`) and defaults for settings the report does not record (exceptions, controls version, policy sources). If the original scan used non-default values for those, the rescan can evaluate different settings — scan again with the original settings when they matter.

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
