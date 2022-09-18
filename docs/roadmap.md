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

* ##### Storing scan results in cluster
  We want Kubescape scan results (both cluster and image scan) to be stored in the cluster locally as `CRD`s. This will enable easier integration with results by other projects as well as with scripting via `kubectl`. This will also make image scan based controls to avoid accessing external resources for image vulnerability scan results.

* ##### Vulnerability prioritization based on workload file activity
  Implementing an eBPF agent (based on Falco or Tracee) which tracks file activity in workloads to prioritize container image vulnerabilities.

* ##### Prioritization engine using MITRE Attack matrix based attack chains
  Create a security issue prioritization engine that scores resources based on control based attack chains. All Kubescape controls can be arranged into attack categories of the MITRE Attack matrix. The Attack matrix categories can be connected to each other based on a theoretical attack (ie. you can't have privilege escalation without initial access). Each of the Kubescape controls is to be categorized in these system and Kubescape will calculate a priority score based on the interconnections between failed controls.

* ##### Integration with image registries 
 We want to expand Kubescape to integrate with different image registries and read image vulnerability information from there. This will allow Kubescape to give contextual security information about vulnerabilities. Container registry integration.
* ##### Kubescape CLI control over cluster operations 
  Add functionality to Kubescape CLI to trigger operations in Kubescape cluster components (example: trigger image scans, etc.)
* ##### Git integration for pull requests 
  Create insightful GitHub actions for Kubescape.


## Backlog 📅
* ##### JSON path for HELM charts 
  Today, Kubescape can point to issues in the Kubernetes object. We want to develop this feature so Kubescape will be able to point to the misconfigured source file (HELM).
* ##### Create Kubescape HELM plugin
  Producing scan results in the context of HELM.
* ##### Kubescape based admission controller 
  Implement admission controller API for Kubescape microservice to enable users to use Kubescape rules as policies.

## Wishlist 💭
* ##### Integrate with other Kubernetes CLI tools
  Use Kubescape as a YAML validator for `kubectl` and others.
* ##### Kubernetes audit log integration 
  Connect Kubescape to the audit log stream to enable it to produce more contextual security information based on how the API service is used.
* ##### TUI for Kubescape 
  Interactive terminal based user interface which helps to analyze and fix issues.
* ##### Scanning images with GO for vulnerabilities
  Images scanners cannot determine which packages were used to build Go executables and we want to scan them for vulnerabilities.
* ##### Scanning Dockerfile-s for security best practices
  Scan image or Dockerfile to determine whether it is using security best practices (like root containers).
* ##### Custom controls and rules
  Enable users to define their own Rego base rules.
* ##### More CI/CD tool integration
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
