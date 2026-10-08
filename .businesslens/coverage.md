---
scope: The Kubescape CLI, its MCP server, the Kubescape Microservice API and the core scanning engine they share.
method: Static inspection of source and supporting documentation; nothing was built or run.
covered:
  - description: CLI scan, image, fleet, contract and preflight commands
    paths: [cmd/scan/, cmd/shared/]
  - description: CLI fix, diff, decrypt, patch, list, download and predict commands
    paths: [cmd/fix/, cmd/diff/, cmd/decrypt/, cmd/patch/, cmd/list/, cmd/download/, cmd/predict/]
  - description: CLI config, operator, admission policy and custom rule commands
    paths: [cmd/config/, cmd/operator/, cmd/vap/, cmd/policy/]
  - description: MCP server and its tools
    paths: [cmd/mcpserver/]
  - description: Microservice API service
    paths: [httphandler/]
  - description: Core scanning, policy, results, fix, report encryption, contract and analysis engine
    paths: [core/core/, core/cautils/, core/meta/, core/pkg/anonymizer/, core/pkg/containerscan/, core/pkg/exposure/, core/pkg/fixhandler/, core/pkg/fleet/, core/pkg/mapreconcile/, core/pkg/networkpolicy/, core/pkg/opaprocessor/, core/pkg/policyhandler/, core/pkg/policytest/, core/pkg/pss/, core/pkg/rbacgraph/, core/pkg/reportcrypto/, core/pkg/resourcehandler/, core/pkg/resourcesprioritization/, core/pkg/resultshandling/, core/pkg/ruledir/, core/pkg/scancache/, core/pkg/scancontract/, core/pkg/score/, core/pkg/securityexception/, core/pkg/telemetry/, core/pkg/vapreconcile/, core/pkg/vulnexposure/]
  - description: Image scanning engine and Kubescape storage connection
    paths: [pkg/]
exclusions:
  - description: Build, release, install, CI and smoke-test tooling
    paths: [build/, .github/, downloader/, smoke_testing/, internal/, Makefile, install.sh, install.ps1, .goreleaser.yaml, .krew.yaml]
  - description: In-tree policy rule development area
    paths: [rules/]
  - description: Example manifests and deployment samples
    paths: [examples/]
  - description: Test doubles for the core engine
    paths: [core/mocks/]
  - description: Documentation and site assets
    paths: [docs/]
unmapped:
  - description: Version, update-check and shell completion commands
    paths: [cmd/version/, cmd/update/, cmd/completion/]
  - description: Root command, global options and backend discovery
    paths: [cmd/root.go, cmd/rootutils.go]
  - description: Registry vulnerability adaptors in the image scanning package
    paths: [pkg/imagescan/azure_adaptor.go, pkg/imagescan/ecr_adaptor.go, pkg/imagescan/gcp_adaptor.go, pkg/imagescan/gitlab_adaptor.go, pkg/imagescan/harbor_adaptor.go, pkg/imagescan/quay_adaptor.go, pkg/imagescan/civ.go]
  - description: Core metrics instrumentation
    paths: [core/metrics/]
limitations:
  - description: Operator installation prerequisites check, whose checks live in an external module
    paths: [cmd/prerequisites/]
  - description: Host data collection, whose collectors live in external modules
    paths: [core/pkg/hostsensorutils/]
---

# Coverage
