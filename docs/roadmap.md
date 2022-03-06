# Kubescape project roadmap

## Planning principles

Kubescape roadmap items are labeled based on where the feature is used and by their maturity.

The features serve different stages of the workflow of the users:
* development phase (writing Kubernetes manifests) - example: VS Code extension is used while editing YAMLs
* CI phase (integrating manifests to GIT repo) - example: GitHub action validating HELM charts on PRs
* delivery phase (deploying applications in Kubernetes) - example: running cluster scan after a new deployment
* monitoring phase (scanning application in Kubernetes) - example: Prometheus scraping the cluster security risk 

Items in Kubescape roadmap are split to 3 major groups based on the feature planning maturity:

* Planning - we have tickets open for these issues with more or less clear vision of design
* Backlog  - feature which were discussed at a high level but are not ready for development 
* Wishlist -  features we are dreaming of 😀 and want to push them gradually forward 


## Planning 👷
* ###### **Integration with image registries**: we want to expand Kubescape to integrate with differnet image registries and read image vulnerability information from there. This will allow Kubescape to give contextual security information about vulnerabilities [Container registry integration](/docs/proposals/container-image-vulnerability-adaptor.md)
* ###### **Kubescape as a microservice**: create a REST API for Kubescape so it can run constantly in a cluster and other components like Prometheus can scrape results
* ###### **Kubescape CLI control over cluster operations**: add functionality to Kubescape CLI to trigger operations in Kubescape cluster components (example: trigger images scans and etc.)
* ###### **Produce md/HTML reports**: create scan reports for different output formats
* ###### **Git integration for pull requests**: create insightful GitHub actions for Kubescape

## Backlog 📅
* ###### **JSON path for HELM charts**: today Kubescape can point to issues in the Kubernetes object, we want to develop this feature so Kubescape will be able to point to the misconfigured source file (HELM)
* ###### **Create Kubescape HELM plugin**
* ###### **Kubescape based admission controller**: Implement admission controller API for Kubescape microservice to enable users to use Kubescape rules as policies

## Wishlist 💭
* ###### **Integrate with other Kubernetes CLI tools** use Kubescape as a YAML validator for `kubectl` and others.
* ###### **Kubernetes audit log integration**: connect Kubescape to audit log stream to enable it to produce more contextual security information based on how the API service is used.
* ###### **TUI for Kubescape**: interactive terminal based user interface which helps to analyze and fix issues
* ###### **Scanning images with GO for vulnerabilities**: Images scanners cannot determine which packages were used to build Go executables and we want to scan them for vulnerabilities
* ###### **Scanning Dockerfile-s for security best practices**: Scan image or Dockerfile to determine whether it is using security best practices (like root containers)
* ###### **Custom controls and rules**: enable users to define their own Rego base rules
* ###### **More CI/CD tool integration**: Jenkins and etc. 😀


## Completed features 🎓
* Kubelet configuration validation 
* API server configuration validation
* Image vulnerability scanning based controls 
* Assisted remediation (telling where/what to fix)
* Integration with Prometheus
* Confiugration of controls (customizing rules for a given environment)
* Installation in the cluster for continous monitoring
* Host scanner 
* Cloud vendor API integration
* Custom exceptions
* Custom frameworks
