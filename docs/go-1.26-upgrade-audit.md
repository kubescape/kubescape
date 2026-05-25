# Go version and GOMEMLIMIT audit (current state)

Date: 2026-05-25
Status: current-state snapshot only (no proposals)

## Scope
This document maps where Go version pins and explicit GOMEMLIMIT settings live in the kubescape repo and the local helm-charts clone. It is a trace guide for new contributors.

Local helm-charts clone used for this audit: ../helm-charts (sibling repo to kubescape in this workspace).

## Trace checklist (fast path)
1) Confirm Go pins in go.mod and httphandler/go.mod.
2) Confirm CI Go pin and GO_VERSION reference in workflows.
3) Confirm the documented Go requirement in build/README.md.
4) Confirm GOMEMLIMIT usage in the local helm-charts clone (kubescape-operator chart values and templates).
5) Use the appendices for exact strings.

## Snapshot notes (current state)
- Go 1.25.9 is pinned in go.mod and httphandler/go.mod.
- Release workflow pins Go 1.25 in actions/setup-go.
- a-pr-scanner uses inputs.GO_VERSION for setup-go; the input is referenced but not declared in that workflow file.
- build/README.md lists Go 1.23+ as a prerequisite.
- Helm-charts kubescape-operator templates set GOMEMLIMIT via resourceFieldRef for kubescape/operator/storage/otel-collector/synchronizer/prometheus-exporter, and via gomemlimit helper for kubevuln and node-agent (including sbom-scanner). values.yaml defines gomemlimitPercentage.

## Kubescape repo trace map
| Area | Files | What to look for |
| --- | --- | --- |
| Go module pin (root) | go.mod | `go 1.25.9` |
| Go module pin (httphandler) | httphandler/go.mod | `go 1.25.9` |
| CI release Go pin | .github/workflows/02-release.yaml | setup-go `go-version: "1.25"` |
| PR scanner Go reference | .github/workflows/a-pr-scanner.yaml | setup-go `go-version: ${{ inputs.GO_VERSION }}` |
| PR scanner caller | .github/workflows/00-pr-scanner.yaml | uses a-pr-scanner |
| Documentation requirement | build/README.md | `Go 1.23+` |

## Helm-charts trace map (local clone)
Local clone root: ../helm-charts

GOMEMLIMIT values:
- charts/kubescape-operator/values.yaml -> `gomemlimitPercentage`

GOMEMLIMIT templates:
- charts/kubescape-operator/templates/kubescape/deployment.yaml
- charts/kubescape-operator/templates/operator/deployment.yaml
- charts/kubescape-operator/templates/kubevuln/deployment.yaml (kubevuln and sbom-scanner)
- charts/kubescape-operator/templates/node-agent/_node-agent.tpl
- charts/kubescape-operator/templates/storage/deployment.yaml
- charts/kubescape-operator/templates/otel-collector/deployment.yaml
- charts/kubescape-operator/templates/synchronizer/deployment.yaml
- charts/kubescape-operator/templates/prometheus-exporter/deployment.yaml

## Deep audit iterations (passes 1-7)
Pass 1 - Go module pins
- go.mod and httphandler/go.mod confirm `go 1.25.9`.

Pass 2 - CI Go pin
- 02-release.yaml pins setup-go to 1.25.

Pass 3 - PR scanner GO_VERSION reference
- a-pr-scanner.yaml uses inputs.GO_VERSION for setup-go.

Pass 4 - PR scanner caller context
- 00-pr-scanner.yaml calls a-pr-scanner.

Pass 5 - Documentation requirement
- build/README.md lists Go 1.23+ in prerequisites.

Pass 6 - Helm-charts values
- values.yaml defines gomemlimitPercentage entries.

Pass 7 - Helm-charts templates
- kubescape-operator templates set GOMEMLIMIT from limits or helper functions.

## Appendix A: evidence locations (kubescape repo)
- go.mod -> `go 1.25.9`
- httphandler/go.mod -> `go 1.25.9`
- .github/workflows/02-release.yaml -> `go-version: "1.25"`
- .github/workflows/a-pr-scanner.yaml -> `go-version: ${{ inputs.GO_VERSION }}`
- .github/workflows/00-pr-scanner.yaml -> `uses: ./.github/workflows/a-pr-scanner.yaml`
- build/README.md -> `Go 1.23+`

## Appendix B: evidence locations (local helm-charts clone)
- charts/kubescape-operator/values.yaml -> `gomemlimitPercentage`
- charts/kubescape-operator/templates/kubescape/deployment.yaml -> `GOMEMLIMIT`
- charts/kubescape-operator/templates/operator/deployment.yaml -> `GOMEMLIMIT`
- charts/kubescape-operator/templates/kubevuln/deployment.yaml -> `GOMEMLIMIT`
- charts/kubescape-operator/templates/node-agent/_node-agent.tpl -> `GOMEMLIMIT`
- charts/kubescape-operator/templates/storage/deployment.yaml -> `GOMEMLIMIT`
- charts/kubescape-operator/templates/otel-collector/deployment.yaml -> `GOMEMLIMIT`
- charts/kubescape-operator/templates/synchronizer/deployment.yaml -> `GOMEMLIMIT`
- charts/kubescape-operator/templates/prometheus-exporter/deployment.yaml -> `GOMEMLIMIT`
