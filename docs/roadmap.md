# Kubescape project roadmap

## Planning principles

Kubescape roadmap items are labeled based on where the feature is used and by their maturity.

The features serve different stages of the workflow of the users:

* **Development phase** (writing Kubernetes manifests) - example: The VS Code extension is used while editing YAMLs.
* **CI phase** (integrating manifests to GIT repo) - example: GitHub action validating HELM charts on PRs.
* **CD phase** (deploying applications in Kubernetes) - example: running a cluster scan after a new deployment.
* **Monitoring phase** (scanning application in Kubernetes) - example: Prometheus scraping the cluster security risk.

The items in the Kubescape roadmap are split into 3 major groups based on the feature planning maturity:

* [Planning](#planning-) - we have tickets open for these issues with a more or less clear vision of design.
* [Backlog](#backlog-)  -  features that were discussed at a high level but are not ready for development.
* [Wishlist](#wishlist-) -  features that we are dreaming of in 😀 and want to push them gradually forward.


## Planning 👷

* ### eBPF based anomaly detection in workloads

The introduction of runtime anomaly detection using eBPF (extended Berkeley Packet Filter) events marks an addition to the Kubescape project's development roadmap. This feature aims to leverage the high-performance monitoring capabilities of eBPF to detect abnormal behavior within Kubernetes workloads in real-time. By capturing and analyzing eBPF events, Kubescape will be able to identify deviations from application profiles, such as unexpected network connections, unauthorized process executions, or unusual system calls, which could indicate a security breach. This anomaly detection mechanism is designed to operate with minimal overhead, ensuring that security monitoring does not compromise system performance.

* ### Enriching Vulnerability scan results with advanced prioritization data sources

Integrating EPSS (Exploit Prediction Scoring System) and CISA-KEV (Known Exploited Vulnerabilities) metrics into Kubescape's CLI and Operator vulnerability scan results represents a significant enhancement in the project's roadmap. This integration aims to enrich the vulnerability management process by providing more contextual and predictive insights into the security risks associated with Kubernetes clusters. By leveraging EPSS scores, Kubescape will offer predictions on the likelihood of a vulnerability being exploited, enabling users to prioritize remediations based on risk rather than just vulnerability presence. The addition of CISA-KEV metrics further enhances this capability by flagging vulnerabilities that are actively being exploited in the wild, as identified by the Cybersecurity and Infrastructure Security Agency (CISA). This dual approach ensures that Kubescape users are not only informed about the vulnerabilities in their environments but are also equipped with critical information on which vulnerabilities to remediate first, based on their exploitability and active exploitation trends. This strategic enhancement to Kubescape's vulnerability scan results will provide users with a powerful tool for making informed, risk-based security decisions in their Kubernetes environments.

* ### Integration with image registries

 We want to expand Kubescape to integrate with different image registries and read image vulnerability information from there. This will allow Kubescape to give contextual security information about vulnerabilities. Container registry integration.

* ### Kubescape CLI control over cluster operations

  Add functionality to Kubescape CLI to trigger operations in Kubescape cluster components (example: trigger image scans, etc.)

* ### Git integration for pull requests

  Create insightful GitHub actions for Kubescape.

## Backlog 📅

* ### JSON path for HELM charts

  Today, Kubescape can point to issues in the Kubernetes object. We want to develop this feature so Kubescape will be able to point to the misconfigured source file (HELM).

* ### Create Kubescape HELM plugin

  Producing scan results in the context of HELM.

* ### Kubescape based admission controller

  Implement admission controller API for Kubescape microservice to enable users to use Kubescape rules as policies.

## Wishlist 💭

* ### Integrate with other Kubernetes CLI tools

  Use Kubescape as a YAML validator for `kubectl` and others.

* ### Kubernetes audit log integration

  Connect Kubescape to the audit log stream to enable it to produce more contextual security information based on how the API service is used.

* ### TUI for Kubescape

  Interactive terminal based user interface which helps to analyze and fix issues.

* ### Scanning images with GO for vulnerabilities

  Images scanners cannot determine which packages were used to build Go executables and we want to scan them for vulnerabilities.

* ### Scanning Dockerfile-s for security best practices

  Scan image or Dockerfile to determine whether it is using security best practices (like root containers).

* ### Custom controls and rules

  Enable users to define their own Rego base rules.

* ### More CI/CD tool integration

  Jenkins and etc. 😀


## Completed features 🎓

* Kubelet configuration validation
* API server configuration validation
* Image vulnerability scanning based controls
* Assisted remediation (telling where/what to fix)
* Integration with Prometheus
* Configuration of controls (customizing rules for a given environment)
* Installation in the cluster for continuous monitoring
* Host scanner
* Cloud vendor API integration
* Custom exceptions
* Custom frameworks
