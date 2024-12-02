[![Version](https://img.shields.io/github/v/release/kubescape/kubescape)](https://github.com/kubescape/kubescape/releases)
[![build](https://github.com/kubescape/kubescape/actions/workflows/02-release.yaml/badge.svg)](https://github.com/kubescape/kubescape/actions/workflows/02-release.yaml)
[![Go Report Card](https://goreportcard.com/badge/github.com/kubescape/kubescape)](https://goreportcard.com/report/github.com/kubescape/kubescape)
[![Gitpod Ready-to-Code](https://img.shields.io/badge/Gitpod-Ready--to--Code-blue?logo=gitpod)](https://gitpod.io/#https://github.com/kubescape/kubescape)
[![GitHub](https://img.shields.io/github/license/kubescape/kubescape)](https://github.com/kubescape/kubescape/blob/master/LICENSE)
[![CNCF](https://shields.io/badge/CNCF-Sandbox%20project-blue?logo=linux-foundation&style=flat)](https://landscape.cncf.io/card-mode?project=sandbox&selected=kubescape)
[![Twitter Follow](https://img.shields.io/twitter/follow/kubescape?style=social)](https://twitter.com/kubescape)

# Kubescape

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/cncf/artwork/master/projects/kubescape/stacked/white/kubescape-stacked-white.svg" width="150">
  <source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/cncf/artwork/master/projects/kubescape/stacked/color/kubescape-stacked-color.svg" width="150">
  <img alt="Kubescape logo" align="right" src="https://raw.githubusercontent.com/cncf/artwork/master/projects/kubescape/stacked/color/kubescape-stacked-color.svg" width="150">
</picture>

_Comprehensive Kubernetes Security from Development to Runtime_

Kubescape is an open-source Kubernetes security platform that provides comprehensive security coverage, from left to right across the entire development and deployment lifecycle. It offers hardening, posture management, and runtime security capabilities to ensure robust protection for Kubernetes environments. It saves Kubernetes users and admins precious time, effort, and resources.

Kubescape scans clusters, YAML files, and Helm charts. It detects misconfigurations according to multiple frameworks (including [NSA-CISA](https://www.armosec.io/blog/kubernetes-hardening-guidance-summary-by-armo/?utm_source=github&utm_medium=repository), [MITRE ATT&CK®](https://www.armosec.io/glossary/mitre-attck-framework/?utm_source=github&utm_medium=repository) and the [CIS Benchmark](https://www.armosec.io/blog/cis-kubernetes-benchmark-framework-scanning-tools-comparison/?utm_source=github&utm_medium=repository)).

Kubescape was created by [ARMO](https://www.armosec.io/?utm_source=github&utm_medium=repository) and is a [Cloud Native Computing Foundation (CNCF) sandbox project](https://www.cncf.io/sandbox-projects/).

## Demo
<img src="docs/img/demo.gif">

_Please [star ⭐](https://github.com/kubescape/kubescape/stargazers) the repo if you want us to continue developing and improving Kubescape! 😀_

## Getting started

Experimenting with Kubescape is as easy as:

```sh
curl -s https://raw.githubusercontent.com/kubescape/kubescape/master/install.sh | /bin/bash
```

Learn more about:

* [Installing Kubescape](docs/installation.md)
* [Running your first scan](docs/getting-started.md#run-your-first-scan)
* [Usage](docs/getting-started.md#examples)
* [Architecture](docs/architecture.md)
* [Building Kubescape from source](https://github.com/kubescape/kubescape/wiki/Building)

_Did you know you can use Kubescape in all these places?_

<div align="center">
    <img src="docs/img/ksfromcodetodeploy.png" alt="Places you can use Kubescape: in your IDE, CI, CD, or against a running cluster.">
</div>

## Under the hood

Kubescape uses [Open Policy Agent](https://github.com/open-policy-agent/opa) to verify Kubernetes objects against [a library of posture controls](https://github.com/kubescape/regolibrary).
For image scanning, it uses [Grype](https://github.com/anchore/grype).  
For image patching, it uses [Copacetic](https://github.com/project-copacetic/copacetic).
For eBPF, it uses [Inspektor Gadget](https://github.com/inspektor-gadget)

By default, the results are printed in a console-friendly manner, but they can be:

* exported to JSON or junit XML
* rendered to HTML or PDF
* submitted to a [cloud service](docs/providers.md)

It retrieves Kubernetes objects from the API server and runs a set of [Rego snippets](https://www.openpolicyagent.org/docs/latest/policy-language/) developed by [ARMO](https://www.armosec.io?utm_source=github&utm_medium=repository).

## Community

Kubescape is an open source project. We welcome your feedback and ideas for improvement. We are part of the CNCF community and are evolving Kubescape in sync with the security needs of Kubernetes users. To learn more about where Kubescape is heading, please check out our [ROADMAP](https://github.com/kubescape/project-governance/blob/main/ROADMAP.md).

If you feel inspired to contribute to Kubescape, check out our [CONTRIBUTING](https://github.com/kubescape/project-governance/blob/main/CONTRIBUTING.md) file to learn how. You can find the issues we are working on (triage to development) on the [Kubescaping board](https://github.com/orgs/kubescape/projects/4/views/1)

* Feel free to pick a task from the [board](https://github.com/orgs/kubescape/projects/4) or suggest a feature of your own.
* Open an issue on the board. We aim to respond to all issues within 48 hours.
* [Join the CNCF Slack](https://slack.cncf.io/) and then our [users](https://cloud-native.slack.com/archives/C04EY3ZF9GE) or [developers](https://cloud-native.slack.com/archives/C04GY6H082K) channel.

The Kubescape project follows the [CNCF Code of Conduct](https://github.com/cncf/foundation/blob/master/code-of-conduct.md).

For more information about the Kubescape community, please visit [COMMUNITY](https://github.com/kubescape/project-governance/blob/main/COMMUNITY.md).

We would like to take this opportunity to thank all our contibutors to date.

<br>

<a href = "https://github.com/kubescape/kubescape/graphs/contributors">
  <img src = "https://contrib.rocks/image?repo=kubescape/kubescape"/>
</a>

## License

Copyright 2021-2024, the Kubescape Authors. All rights reserved. Kubescape is released under the Apache 2.0 license. See the [LICENSE](LICENSE) file for details.

Kubescape is a [Cloud Native Computing Foundation (CNCF) sandbox project](https://www.cncf.io/sandbox-projects/) and was contributed by [ARMO](https://www.armosec.io/?utm_source=github&utm_medium=repository).

<div align="center">
    <img src="https://raw.githubusercontent.com/cncf/artwork/master/other/cncf-sandbox/horizontal/color/cncf-sandbox-horizontal-color.svg" width="300" alt="CNCF Sandbox Project">
</div>
