# Kubescape security self-assessment

> **Assessment stage: Incomplete.** This evidence-backed draft updates the assessment prepared for the Kubescape CNCF incubation review in December 2024. It has not yet been reviewed or approved by Kubescape maintainers. Open questions are marked `TODO(maintainer)`; this document does not claim an independent audit or certification.

| Metadata | Value |
| --- | --- |
| Software | [Kubescape](https://github.com/kubescape/kubescape) |
| Security provider | Yes. Kubescape assesses Kubernetes and container security; this does not establish the security of a deployment. |
| Languages | Go and supporting shell, YAML, and configuration files; see the repository for the current inventory. |
| Assessment basis | Source and documentation at repository revision `369227dbd620665b8b31e99712643ed215c4c904`; see linked component repositories for their separately versioned code. |
| Prepared | 2026-10-09 |
| Historical source | [CNCF TOC incubation self-assessment (2024-12-10)](https://github.com/cncf/toc/blob/main/projects/kubescape/security-assessment/self-assessment.md), prepared by Ben Hirschberg. Kept as historical attribution. |

## Table of contents

- [Security links](#security-links)
- [Overview](#overview)
  - [Actors and actions](#actors-and-actions)
  - [Background](#background)
  - [Goals and non-goals](#goals-and-non-goals)
- [Assessment use](#assessment-use)
- [Security functions and threat assessment](#security-functions-and-threat-assessment)
  - [CLI and local inputs](#cli-and-local-inputs)
  - [ksserver API](#ksserver-api)
  - [MCP server](#mcp-server)
  - [Operator, admission, and cluster writes](#operator-admission-and-cluster-writes)
  - [Storage and workload profiles](#storage-and-workload-profiles)
  - [Image patching and manifest fixes](#image-patching-and-manifest-fixes)
  - [Build and release supply chain](#build-and-release-supply-chain)
- [Project compliance and security practices](#project-compliance-and-security-practices)
  - [Ecosystem](#ecosystem)
  - [Security issue resolution](#security-issue-resolution)
- [Case studies](#case-studies)
- [Related projects](#related-projects)
- [Appendix](#appendix)

## Security links

| Document | Purpose |
| --- | --- |
| [Security policy](https://github.com/kubescape/project-governance/blob/main/SECURITY.md) | Private vulnerability reporting and disclosure process. |
| [Contributing guide](https://github.com/kubescape/project-governance/blob/main/CONTRIBUTING.md) | Contribution requirements. |
| [CLI reference](../cli-reference.md) | CLI flags, output handling, and image scanning. |
| [MCP server guide](../mcp-server.md) | MCP server setup and tool behavior. |
| [Architecture guide](../architecture.md) | CLI and service architecture. |
| [Release workflow guide](../../.github/workflows/README.md) | Release and artifact verification instructions. |

## Overview

Kubescape is an open source Kubernetes security project. Its CLI and related services scan Kubernetes configuration, workloads, and container images; the operator and associated components collect runtime information and can support configured remediation workflows.

This assessment describes the project behavior visible in the cited source and public documentation. A deployment's protection depends on its Kubernetes permissions, enabled components, network exposure, selected configuration, and operator practices.

### Actors and actions

| Actor | Inputs and actions | Security boundary |
| --- | --- | --- |
| CLI user and local host | Select kubeconfig, manifests, policies, image references, output, and optional submission. | Local credentials, files, downloaded content, and report destinations. |
| Kubernetes API server | Authenticates the configured identity and applies its RBAC permissions to CLI, operator, MCP, and synchronizer requests. | Cluster identity, authorization, and admission configuration. |
| CLI and ksserver | Evaluate local or cluster inputs; ksserver exposes selected HTTP APIs for in-cluster integrations. | Local process access and, when configured, network and bearer-token boundaries. |
| Operator, node-agent, storage, synchronizer | Observe cluster resources, write profile and status resources, and perform selected actions subject to configuration and RBAC. | Workload data and any cluster write permission granted to service accounts. |
| MCP client and server | Exchange tool requests over standard input/output; the server uses its configured Kubernetes access for tools. | Local MCP client trust and the server's inherited cluster authority. |
| Build and release automation | Build, package, sign, and publish project artifacts. | Source review, CI credentials, signing identities, registry credentials, and release outputs. |

### Background

Kubescape is a security assessment tool, not a Kubernetes authorization or isolation boundary. Its scan findings depend on the frameworks, rules, data sources, and permissions available during a scan. An assessment result alone does not enforce remediation or prove that a cluster is secure.

### Goals and non-goals

This document identifies important software and operational boundaries, plausible misuse, current controls, and residual risks to help maintainers and downstream users make deployment decisions.

It is not a penetration test, independent audit, guarantee of exploit resistance, complete threat model for every deployment, or certification. It does not assert that every optional protection is enabled by default.

## Assessment use

Use this assessment to identify questions for a deployment review. Confirm the exact Kubescape version, enabled components, Kubernetes RBAC, network exposure, selected policy sources, report destinations, and release verification procedure. Revisit the assessment when these boundaries or the implementation change.

The assessment maps to the purpose of [OSPS-SA-03.01](https://baseline.openssf.org/versions/2026-08-28/#osps-sa-0301): describe likely and impactful security problems. The existence of this file does not by itself prove that the control is met or that a scanner will accept the project's evidence.

## Security functions and threat assessment

Likelihood below is qualitative and refers to a misconfiguration or misuse in a deployment, not measured incident frequency. Impact can be high where Kubernetes credentials, workload data, or release artifacts are exposed. The controls listed are the ones verified in the cited project code or documentation; operators must verify configuration in their own environment.

### CLI and local inputs

The CLI can read local manifests, use kubeconfig credentials to query a cluster, download policies and vulnerability data, and optionally submit results to a configured backend. The `--submit` flag opts into Kubescape SaaS submission; `--keep-local` disables reporting. These choices and flags do not make arbitrary report files safe to share.

**Threat assessment:** A user can select an untrusted policy or manifest, expose a kubeconfig, submit results to an unintended service, or disclose a report containing environment and resource details. The likelihood is configuration-dependent because the user selects inputs, credential source, output, and submission behavior. Impact ranges from misleading scan results to cluster access or disclosure of sensitive infrastructure details.

**Controls and residual risk:** Kubernetes RBAC remains the authority for cluster operations. By default, Secret and ConfigMap values are redacted from evidence; `--show-secrets` can reveal them. `--hide` replaces selected metadata with deterministic pseudonyms and is not encryption. `--encrypt` encrypts supported report metadata when a separately protected `KUBESCAPE_MASTER_KEY` is supplied; not every output format or field is covered. Users must protect kubeconfig files, downloaded artifacts, output files, encryption keys, and any configured submission credentials, and review the destination and report contents before sharing.

Sources: [scan flags and report handling](https://github.com/kubescape/kubescape/blob/369227dbd620665b8b31e99712643ed215c4c904/cmd/scan/scan.go), [CLI reference](../cli-reference.md#hiding-sensitive-metadata), [getting started](../getting-started.md#use-an-alternative-kubeconfig-file).

### ksserver API

ksserver exposes HTTP API routes for integrations. `KS_API_TOKEN` enables optional bearer-token authentication; the in-cluster deployment can run without it. TLS is configured when both `KS_CERT_FILE` and `KS_KEY_FILE` are supplied. Health and OpenAPI endpoints have their own exposure behavior.

**Threat assessment:** An accidentally network-reachable instance without a token or TLS can expose API operations and data to callers on that network. Likelihood depends on service, ingress, and network policy configuration. Impact depends on reachable routes and the service account's cluster access.

**Controls and residual risk:** Restrict network reachability and Kubernetes permissions. Configure a token and TLS when callers cross a boundary that requires them, and verify ingress termination, health paths, and documentation routes in the actual deployment. Optional authentication and TLS do not establish that all routes or upstream proxies are correctly protected.

Sources: [ksserver setup](https://github.com/kubescape/kubescape/blob/369227dbd620665b8b31e99712643ed215c4c904/httphandler/listener/setup.go), [ksserver trust boundary documentation](https://github.com/kubescape/kubescape/blob/369227dbd620665b8b31e99712643ed215c4c904/httphandler/README.md), [authentication change #3461](https://github.com/kubescape/kubescape/pull/3461).

### MCP server

The MCP server uses stdio transport and the Kubernetes configuration available to its process. Its tools can read stored scan results and ContainerProfiles, inspect live cluster state, and run scans; its access is therefore not limited to reading a local cache.

**Threat assessment:** An untrusted MCP client or prompt could request sensitive cluster data, cause expensive scans, or misuse actions available to the configured identity. Likelihood depends on which clients can launch or communicate with the process and on its kubeconfig and RBAC. Impact can include disclosure of workload metadata and resource consumption; any resulting cluster operation remains subject to Kubernetes authorization.

**Controls and residual risk:** Treat the MCP client, host, environment, and kubeconfig as trusted administrative components. Grant only required RBAC and avoid exposing sensitive tool output to untrusted model providers or logs. Stdio avoids a project-hosted remote listener, but does not protect data from the local client or its model service.

Sources: [MCP server startup](https://github.com/kubescape/kubescape/blob/369227dbd620665b8b31e99712643ed215c4c904/cmd/mcpserver/mcpserver.go), [MCP guide](../mcp-server.md).

### Operator, admission, and cluster writes

The operator and node-agent observe cluster state and publish or consume Kubescape resources. The admission webhook queues evaluations asynchronously; its chart configuration uses `failurePolicy: Ignore`. It should be treated as observation and alerting, not as a blocking control that rejects unsafe admission requests.

The synchronizer can write selected workload, network-policy, and seccomp changes when workload management is enabled and its Kubernetes identity has the required permissions. Its write scope is therefore deployment- and RBAC-dependent. Existing operator commands also have action-specific handlers and safeguards; this assessment does not characterize the entire command system as inert or as a process-killing mechanism.

**Threat assessment:** Excessive service-account permissions, a compromised controller, or incorrect admission assumptions can allow unauthorized changes or leave workloads admitted without Kubescape evaluation. Likelihood depends on installed components, chart values, and RBAC. Impact may include workload disruption, security-policy changes, or a false expectation of admission enforcement.

**Controls and residual risk:** Review chart values and rendered RBAC, limit service-account permissions, and use Kubernetes audit and change controls. The queue is bounded, and overload can drop evaluations; `Ignore` allows API requests to continue when the webhook does not provide enforcement. Confirm the actual admission configuration if enforcement is required.

Sources: [node-agent resource watcher](https://github.com/kubescape/node-agent/blob/b1fa98fc5c32cb929b7a827ef9f981e58f7f0179/pkg/watcher/dynamicwatcher/watch.go), [admission validator](https://github.com/kubescape/operator/blob/54a3272fc3f2c63fd8f3b97d8ad4ec173f5322ed9/admission/webhook/validator.go), [webhook chart template](https://github.com/kubescape/helm-charts/blob/6459138afee203396f39e1dd6da9af8528126a7e/charts/kubescape-operator/templates/operator/admission-webhook/webhook.yaml), [synchronizer client](https://github.com/kubescape/synchronizer/blob/2833a6afd17ea03c045fb4aa3ab98769b834c993/adapters/incluster/v1/client.go), [synchronizer RBAC](https://github.com/kubescape/helm-charts/blob/6459138afee203396f39e1dd6da9af8528126a7e/charts/kubescape-operator/templates/synchronizer/clusterrole.yaml).

### Storage and workload profiles

Current storage APIs include `ContainerProfile`, which contains observed container behavior used for drift and hardening workflows. The older ApplicationProfile and NetworkNeighborhood resource descriptions in the 2024 assessment no longer describe the current storage API.

**Threat assessment:** Profile data can reveal software, processes, and workload behavior. Broad read permissions or retention in an unintended namespace can expose operational information. Likelihood and impact depend on the cluster's collected data and RBAC.

**Controls and residual risk:** Apply namespace and service-account restrictions, secure backups, and define retention for profile data. A profile is observational input; consumers should validate it before using it to change workload configuration.

Sources: [ContainerProfile API](https://github.com/kubescape/storage/blob/30a8829ddb83974fe618e31c68022723e2a9d5a5/pkg/apis/softwarecomposition/v1beta1/types.go), [synchronizer](https://github.com/kubescape/synchronizer/blob/2833a6afd17ea03c045fb4aa3ab98769b834c993/adapters/incluster/v1/client.go).

### Image patching and manifest fixes

`kubescape patch` builds a patched image using image-building components and registry inputs. `kubescape fix` changes local manifest files in place unless an output directory is selected; for a cluster scan it prints proposed manifests for review and application. These workflows have different inputs and effects.

**Threat assessment:** Untrusted base images, registry credentials, or unreviewed generated changes can introduce vulnerable or unintended artifacts or modify manifests. Likelihood depends on source provenance, credential handling, and automation choices. Impact can include publishing a compromised image or changing a deployed workload after a user applies output.

**Controls and residual risk:** Protect registry credentials, verify image sources, review generated changes, and use dry-run or output-directory workflows where appropriate. A successful patch or fix does not establish that the resulting artifact is safe or that a cluster change is correct.

Sources: [patch command](https://github.com/kubescape/kubescape/blob/369227dbd620665b8b31e99712643ed215c4c904/cmd/patch/patch.go), [fix command](https://github.com/kubescape/kubescape/blob/369227dbd620665b8b31e99712643ed215c4c904/cmd/fix/fix.go), [fix behavior](../getting-started.md#auto-fix-misconfigurations).

### Build and release supply chain

The release configuration builds platform-specific CLI and service artifacts, generates SBOMs, signs checksum manifests, and the release workflow attests build provenance for configured outputs. These mechanisms cover distinct properties: an SBOM lists components, a signature authenticates a signed artifact under an identity, and provenance describes a build. Their presence does not prove that a user has verified a particular download.

**Threat assessment:** A compromised source revision, workflow, signing identity, dependency, or registry could affect published artifacts. Likelihood depends on repository, CI, and credential controls. Impact is high if a malicious artifact reaches cluster administrators.

**Controls and residual risk:** Changes require review under current repository rules; release automation produces checksums, signatures, SBOMs, and provenance as configured. Verify signature identity and provenance for the exact artifact, protect release permissions, and review generated dependency updates. `TODO(maintainer)`: confirm whether published image signatures and all release artifact attestations are externally verifiable and document the supported verification commands for each distribution channel.

Sources: [GoReleaser configuration](https://github.com/kubescape/kubescape/blob/369227dbd620665b8b31e99712643ed215c4c904/.goreleaser.yaml), [release workflow](https://github.com/kubescape/kubescape/blob/369227dbd620665b8b31e99712643ed215c4c904/.github/workflows/02-release.yaml), [release documentation](../../.github/workflows/README.md).

## Project compliance and security practices

This assessment reports implementation evidence and identified assumptions. It does not declare compliance with OSPS or any certification.

The repository's `master` ruleset currently requires one approval. Do not repeat the older claim that every pull request receives multiple approvals. `TODO(maintainer)`: confirm review exceptions, security-sensitive review expectations, and controls on CI and release credentials.

The repository publishes Go module, workflow, and release configuration. The exact security scanners, cadence, and results are described in [`security-insights.yml`](../../security-insights.yml); that file is machine-readable project metadata and should not be read as proof that a tool found no vulnerabilities.

### Ecosystem

Kubescape is an open source project with a community repository and separately maintained component repositories. [ARMO](https://www.armosec.io/) offers commercial products based on Kubescape; commercial offerings, hosted services, support, and controls may differ from the community software described here. Do not infer that the open source project operates or secures ARMO services.

`TODO(maintainer)`: identify which upstream and downstream projects are in scope for this assessment and confirm any comparative claims before publication.

## Security issue resolution

The canonical [Kubescape security policy](https://github.com/kubescape/project-governance/blob/main/SECURITY.md) directs reporters to private GitHub security advisories and describes a response target and coordinated disclosure process. Use that policy for suspected vulnerabilities; do not publish details of an unpatched, exploitable issue in this assessment or a public issue.

`TODO(maintainer)`: confirm the response-time wording against the current governance policy and identify any project-specific escalation or incident roles that are suitable for public documentation. No private incident history is asserted here.

## Case studies

The CNCF incubation due-diligence material records historical adopter interviews. It describes a Bitnami/Broadcom packaging and catalog use case, a KYOS Energy Consulting use case delivered through ARMO, and an anonymous financial-services organization using staged pipeline scans. These are historical examples from the cited application, not endorsements, current deployments, independently measured outcomes, or evidence that the same configuration is secure today.

Source: [Kubescape CNCF incubation proposal](https://github.com/cncf/toc/blob/main/projects/kubescape/kubescape-incubation-proposal.md). `TODO(maintainer)`: verify the names, wording, and permission to retain these examples before marking the assessment complete.

## Related projects

Related project and vendor relationships should be described without unsupported claims about comparative security, features, or market position. ARMO's relationship is summarized in [Ecosystem](#ecosystem).

`TODO(maintainer)`: name any open source projects that maintainers consider useful comparators and provide approved, source-backed descriptions. No comparative security ranking is made in this draft.

## Appendix

### Review record

- Assessment stage: **Incomplete; maintainer review pending**.
- Preparation date: 2026-10-09.
- Repository revision inspected: `369227dbd620665b8b31e99712643ed215c4c904`.
- Related repository revisions are linked at the relevant claims.
- Historical assessment date: 2024-12-10.
- `TODO(maintainer)`: review component boundaries, residual-risk statements, case-study attribution, incident-response wording, ecosystem scope, and remaining questions.

### Completion criteria

Before changing the assessment stage to **Complete**, maintainers should review the threat analysis and resolve or explicitly accept each `TODO(maintainer)`. The assessment's preparation, publication, and review dates must describe events that actually occurred. Update the documentation index and Security Insights metadata with the accepted version, then rerun repository validation.
