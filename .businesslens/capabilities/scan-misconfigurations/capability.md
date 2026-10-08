---
domain: scan
availability:
  - { place: cli }
  - { place: mcp-server }
  - { place: microservice-api }
references:
  - kind: code
    role: implementation
    target: cmd/scan/scan.go#GetScanCommand
  - kind: code
    role: implementation
    target: cmd/scan/framework.go#runFrameworkScan
  - kind: code
    role: implementation
    target: core/core/scan.go#ScanContext
  - kind: code
    role: implementation
    target: core/pkg/policyhandler/handlepullpolicies.go#getPolicies
  - kind: code
    role: implementation
    target: cmd/mcpserver/scan_helper.go#executeScan
  - kind: code
    role: implementation
    target: httphandler/handlerequests/v1/requestshandler.go#Scan
  - kind: code
    role: implementation
    target: core/core/baseline.go#EnforceBaseline
  - kind: doc
    role: intent
    target: docs/cli-reference.md
---

# Scan for misconfigurations

Evaluate Kubernetes resources against security frameworks and controls and
report how they fare. The resources come from a live cluster reached through a
kube context, or from local YAML and JSON files, Helm charts, Kustomize
directories, Terraform or a cloned Git repository; a scan can be narrowed to
named frameworks, named controls, one workload, namespaces or a label
selector. Without a named framework, the default security view evaluates a
cluster against the cluster, MITRE and NSA frameworks and files against the
workload and all-controls frameworks; other views evaluate the all-controls, NSA
and MITRE frameworks. Exceptions, control configuration and custom rules shape the
evaluation, and thresholds on severity, compliance and coverage, degraded
policy inputs and new findings against a saved baseline decide the exit status.
