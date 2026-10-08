---
id: kubescape
summary: Open-source Kubernetes security platform that scans clusters, manifests and container images for misconfigurations and vulnerabilities, and helps fix what it finds.
category: kubernetes-security
tags: [kubernetes, security, compliance, misconfiguration, vulnerability-scanning, admission-control, mcp]
authors:
  - name: The Kubescape Authors
    url: https://kubescape.io
license: Apache-2.0
languages: [en]
limitations:
  - Kubescape never applies a fix, a patched manifest or an admission policy to a cluster; it prints or writes them for people to review and apply.
  - Continuous in-cluster scanning, runtime profiling and workload remediation are carried out by the separately installed Kubescape Operator; Kubescape asks it to act and reads what it keeps, and the Operator's acknowledgement is not completion.
  - Live cluster work uses the credentials of the kubeconfig or service account Kubescape runs with, and sees only what they may read.
  - Frameworks, controls and default exceptions come from the regolibrary release or a Kubescape Cloud account; Kubescape does not author them.
  - Image vulnerabilities are matched against the Grype vulnerability database, and images are patched with Copacetic through a BuildKit daemon.
  - Kubescape keeps no accounts of its own; results submitted to Kubescape Cloud are kept there.
  - A passing scan covers only the frameworks, controls and resources it could evaluate; the scan coverage score reports what it could not.
  - Anonymized report metadata reduces incidental exposure but is not confidential; only encrypted metadata is protected.
references:
  - kind: doc
    role: context
    target: README.md
  - kind: doc
    role: context
    target: docs/architecture.md
  - kind: doc
    role: context
    target: docs/cli-reference.md
  - kind: code
    role: implementation
    target: cmd/root.go#getRootCmd
---

# Kubescape

Kubescape assesses the security posture of Kubernetes environments from
development to runtime. People run it against a live cluster, a set of
manifests, Helm charts, Kustomize directories or a Git repository to evaluate
resources against security frameworks such as NSA-CISA, MITRE ATT&CK and the CIS
Benchmark, and against container images to find known vulnerabilities. It
reports compliance and coverage scores, gates pipelines on thresholds and
baselines, fixes misconfigured manifests, patches vulnerable images, generates
admission policy bindings, and predicts the effect of enforcing Pod Security
Standards.

The same scanning is offered to AI agents through an MCP server, which also
answers questions about the data the Kubescape Operator keeps in a cluster, and
to in-cluster programs through the Kubescape Microservice API.

## Intent

Give Kubernetes users one tool that finds security problems wherever their
resources live — in source, in CI and in the running cluster — and helps them
act on the findings without ever changing a cluster on their behalf.
