# Getting started with Kubescape

Kubescape can run as a command line tool on a client, as an operator inside a cluster, as part of your CI/CD process, or more.  

The best way to get started with Kubescape is to download it to the machine you use to manage your Kubernetes cluster.

## Install Kubescape

```bash
curl -s https://raw.githubusercontent.com/kubescape/kubescape/master/install.sh | /bin/bash
```

(We're a security product; please read the file before you run it!)

You can also check [other installation methods](installation.md)

## Run your first scan

```bash
kubescape scan
```

You will see output like this:

```bash
Kubescape security posture overview for cluster: minikube

In this overview, Kubescape shows you a summary of your cluster security posture, including the number of users who can perform administrative actions. For each result greater than 0, you should evaluate its need, and then define an exception to allow it. This baseline can be used to detect drift in future.

Control plane
┌────┬─────────────────────────────────────┬──────────────────────────────────────────────┐
│    │ Control Name                        │ Docs                                         │
├────┼─────────────────────────────────────┼──────────────────────────────────────────────┤
│ ✅ │ API server insecure port is enabled │ https://kubescape.io/docs/controls/c-0005/   │
│ ❌ │ Anonymous access enabled            │ https://kubescape.io/docs/controls/c-0262/   │
│ ❌ │ Audit logs enabled                  │ https://kubescape.io/docs/controls/c-0067/   │
│ ✅ │ RBAC enabled                        │ https://kubescape.io/docs/controls/c-0088/   │
│ ❌ │ Secret/etcd encryption enabled      │ https://kubescape.io/docs/controls/c-0066/   │
└────┴─────────────────────────────────────┴──────────────────────────────────────────────┘

Access control
┌─────────────────────────────────────────────────┬───────────┬────────────────────────────────────┐
│ Control Name                                    │ Resources │ View Details                       │
├─────────────────────────────────────────────────┼───────────┼────────────────────────────────────┤
│ Cluster-admin binding                           │     1     │ $ kubescape scan control C-0035 -v │
│ Data Destruction                                │     6     │ $ kubescape scan control C-0007 -v │
│ Exec into container                             │     1     │ $ kubescape scan control C-0002 -v │
│ List Kubernetes secrets                         │     6     │ $ kubescape scan control C-0015 -v │
│ Minimize access to create pods                  │     2     │ $ kubescape scan control C-0188 -v │
│ Minimize wildcard use in Roles and ClusterRoles │     1     │ $ kubescape scan control C-0187 -v │
│ Portforwarding privileges                       │     1     │ $ kubescape scan control C-0063 -v │
│ Validate admission controller (mutating)        │     0     │ $ kubescape scan control C-0039 -v │
│ Validate admission controller (validating)      │     0     │ $ kubescape scan control C-0036 -v │
└─────────────────────────────────────────────────┴───────────┴────────────────────────────────────┘

Secrets
┌─────────────────────────────────────────────────┬───────────┬────────────────────────────────────┐
│ Control Name                                    │ Resources │ View Details                       │
├─────────────────────────────────────────────────┼───────────┼────────────────────────────────────┤
│ Applications credentials in configuration files │     1     │ $ kubescape scan control C-0012 -v │
└─────────────────────────────────────────────────┴───────────┴────────────────────────────────────┘

Network
┌────────────────────────┬───────────┬────────────────────────────────────┐
│ Control Name           │ Resources │ View Details                       │
├────────────────────────┼───────────┼────────────────────────────────────┤
│ Missing network policy │    13     │ $ kubescape scan control C-0260 -v │
└────────────────────────┴───────────┴────────────────────────────────────┘

Workload
┌─────────────────────────┬───────────┬────────────────────────────────────┐
│ Control Name            │ Resources │ View Details                       │
├─────────────────────────┼───────────┼────────────────────────────────────┤
│ Host PID/IPC privileges │     2     │ $ kubescape scan control C-0038 -v │
│ HostNetwork access      │     1     │ $ kubescape scan control C-0041 -v │
│ HostPath mount          │     1     │ $ kubescape scan control C-0048 -v │
│ Non-root containers     │     6     │ $ kubescape scan control C-0013 -v │
│ Privileged container    │     1     │ $ kubescape scan control C-0057 -v │
└─────────────────────────┴───────────┴────────────────────────────────────┘

Highest-stake workloads
────────────────────────
High-stakes workloads are defined as those which Kubescape estimates would have the highest impact if they were to be exploited.

1. namespace: gadget, name: gadget, kind: DaemonSet
   '$ kubescape scan workload DaemonSet/gadget --namespace gadget'
2. namespace: kafka, name: my-cluster-kafka-0, kind: Pod
   '$ kubescape scan workload Pod/my-cluster-kafka-0 --namespace kafka'
3. namespace: kafka, name: my-cluster-zookeeper-0, kind: Pod
   '$ kubescape scan workload Pod/my-cluster-zookeeper-0 --namespace kafka'

Compliance Score
────────────────
The compliance score is calculated by multiplying control failures by the number of failures against supported compliance frameworks. Remediate controls, or configure your cluster baseline with exceptions, to improve this score.

* MITRE: 77.39%
* NSA: 69.97%

View a full compliance report by running '$ kubescape scan framework nsa' or '$ kubescape scan framework mitre'

What now?
─────────
* Run one of the suggested commands to learn more about a failed control failure
* Scan a workload with '$ kubescape scan workload' to see vulnerability information
* Install Kubescape in your cluster for continuous monitoring and a full vulnerability report: https://github.com/kubescape/helm-charts/tree/main/charts/kubescape-operator

```

# Usage

Capabilities
* Scan Kubernetes clusters for misconfigurations
* Scan Kubernetes YAML files/Helm charts for misconfigurations
* Scan container images for vulnerabilities

## Misconfigurations Scanning
Scan Kubernetes clusters, YAML files, Helm charts for misconfigurations.
Kubescape will highlight the misconfigurations and provide remediation steps.
The misconfigurations are based on multiple frameworks (including [NSA-CISA](https://www.armosec.io/blog/kubernetes-hardening-guidance-summary-by-armo/?utm_source=github&utm_medium=repository), [MITRE ATT&CK®](https://www.microsoft.com/security/blog/2021/03/23/secure-containerized-environments-with-updated-threat-matrix-for-kubernetes/) and the [CIS Benchmark](https://www.armosec.io/blog/cis-kubernetes-benchmark-framework-scanning-tools-comparison/?utm_source=github&utm_medium=repository)).

### Examples

#### Scan a running Kubernetes cluster:

```bash
kubescape scan
```

> **Note**  
> [Read more about host scanning](https://hub.armosec.io/docs/host-sensor?utm_source=github&utm_medium=repository).

#### Scan NSA framework
Scan a running Kubernetes cluster with the [NSA framework](https://www.nsa.gov/Press-Room/News-Highlights/Article/Article/2716980/nsa-cisa-release-kubernetes-hardening-guidance/):

```bash
kubescape scan framework nsa
```

#### Scan MITRE framework
Scan a running Kubernetes cluster with the [MITRE ATT&CK® framework](https://www.microsoft.com/security/blog/2021/03/23/secure-containerized-environments-with-updated-threat-matrix-for-kubernetes/):

```bash
kubescape scan framework mitre
```

#### Scan a control
Scan for a specific control, using the control name or control ID. [See the list of controls](https://hub.armosec.io/docs/controls?utm_source=github&utm_medium=repository).

```bash
kubescape scan control c-0005 -v
```

#### Use an alternative kubeconfig file

```bash
kubescape scan --kubeconfig cluster.conf
```

#### Scan specific namespaces

```bash
kubescape scan --include-namespaces development,staging,production
```

#### Exclude certain namespaces

```bash
kubescape scan --exclude-namespaces kube-system,kube-public
```

#### Scan local YAML files
```sh
kubescape scan /path/to/directory-or-directory
```

Take a look at the [example](https://youtu.be/Ox6DaR7_4ZI).

#### Scan git repository
Scan Kubernetes manifest files from a Git repository:

```bash
kubescape scan https://github.com/kubescape/kubescape
```

#### Scan with exceptions

```bash
kubescape scan --exceptions examples/exceptions/exclude-kube-namespaces.json
```

Objects with exceptions will be presented as `exclude` and not `fail`.

[See more examples about exceptions.](/examples/exceptions/README.md)

#### Scan Helm charts 

```bash
kubescape scan </path/to/directory>
```

> **Note**  
> Kubescape will load the default VALUES file.

#### Scan a Kustomize directory 

```bash
kubescape scan </path/to/directory>
```

> **Note**  
> Kubescape will generate Kubernetes YAML objects using a `kustomize` file and scan them for security.

#### Trigger in cluster components for scanning your cluster

If the [kubescape-operator](https://github.com/kubescape/helm-charts/tree/main/charts/kubescape-operator#readme) is installed in your cluster, you can trigger scanning of the in cluster components from the kubescape CLI.

Trigger configuration scanning:
```bash
kubescape operator scan configurations
```

Trigger vulnerabilities scanning:
```bash
kubescape operator scan vulnerabilities
```

#### Compliance Score

We offer two important metrics to assess compliance:

- Control Compliance Score: This score measures the compliance of individual controls within a framework. It is calculated by evaluating the ratio of resources that passed to the total number of resources evaluated against that control.
    ```bash
    kubescape scan --compliance-threshold <SCORE_VALUE[float32]>
    ```
- Framework Compliance Score: This score provides an overall assessment of your cluster's compliance with a specific framework. It is calculated by averaging the Control Compliance Scores of all controls within the framework.
    ```bash
    kubescape scan framework <FRAMEWORK_NAME> --compliance-threshold <SCORE_VALUE[float32]>
    ```

### Output formats

#### JSON:

```bash
kubescape scan --format json --output results.json
```

#### junit XML: 

```bash
kubescape scan --format junit --output results.xml
```
#### SARIF: 

SARIF is a standard format for the output of static analysis tools. It is supported by many tools, including GitHub Code Scanning and Azure DevOps. [Read more about SARIF](https://docs.github.com/en/code-security/secure-coding/sarif-support-for-code-scanning/about-sarif-support-for-code-scanning).

```bash
kubescape scan --format sarif --output results.sarif
```
> **Note**
> SARIF format is supported only when scanning local files or git repositories, but not when scanning a running cluster.

#### HTML

```bash
kubescape scan --format html --output results.html
```

## Offline/air-gapped environment support

It is possible to run Kubescape offline!  Check out our [video tutorial](https://youtu.be/IGXL9s37smM).

### Download all artifacts

1. Download the controls and save them in the local directory.  If no path is specified, they will be saved in `~/.kubescape`.

   ```bash
   kubescape download artifacts --output path/to/local/dir
   ```

2. Copy the downloaded artifacts to the offline system.

3. Scan using the downloaded artifacts:

   ```bash
   kubescape scan --use-artifacts-from path/to/local/dir
   ```

### Download a single artifact

You can also download a single artifact, and scan with the `--use-from` flag:

1. Download and save in a file. If no file name is specified, the artifact will be saved as `~/.kubescape/<framework name>.json`.

    ```bash
    kubescape download framework nsa --output /path/nsa.json
    ```

2. Copy the downloaded artifacts to the offline system.

3. Scan using the downloaded framework:

    ```bash
    kubescape scan framework nsa --use-from /path/nsa.json
    ```
## Image scanning

Kubescape can scan container images for vulnerabilities.  It uses [Grype]() to scan the images.

### Examples

#### Scan image

```bash
kubescape scan image nginx:1.19.6
```

#### Scan image from a private registry

```bash
kubescape scan image --username myuser --password mypassword myregistry/nginx:1.19.6
```

#### Scan image and see full report
    
```bash
kubescape scan image nginx:1.19.6 -v
```

## Other ways to use Kubescape

### Scan periodically using Helm 

We publish [a Helm chart](https://github.com/kubescape/helm-charts) for our in-cluster components. [Please follow the instructions here](https://hub.armosec.io/docs/installation-of-armo-in-cluster?utm_source=github&utm_medium=repository)

### VS Code Extension 

![Visual Studio Marketplace Downloads](https://img.shields.io/visual-studio-marketplace/d/kubescape.kubescape?label=VScode) ![Open VSX](https://img.shields.io/open-vsx/dt/kubescape/kubescape?label=openVSX&color=yellowgreen)

Scan your YAML files while writing them using our [VS Code extension](https://github.com/armosec/vscode-kubescape/blob/master/README.md).

### Lens Extension

View Kubescape scan results directly in the [Lens IDE](https://k8slens.dev/) using the [Kubescape Lens extension](https://github.com/armosec/lens-kubescape/blob/master/README.md).

## Playground

Experiment with Kubescape in the [Kubescape playground](https://killercoda.com/saiyampathak/scenario/kubescape): this scenario will install a K3s cluster and Kubescape.  You can start with any of the `kubescape scan` commands in the [examples](#examples).

## Tutorial videos

* [Kubescape overview](https://youtu.be/wdBkt_0Qhbg)
* [How to secure Kubernetes clusters with Kubescape](https://youtu.be/ZATGiDIDBQk)
* [Scan Kubernetes YAML files](https://youtu.be/Ox6DaR7_4ZI)
* [Scan container image registry](https://youtu.be/iQ_k8EnK-3s)
* [Scan Kubescape on an air-gapped environment (offline support)](https://youtu.be/IGXL9s37smM)
* [Managing exceptions in ARMO Platform](https://youtu.be/OzpvxGmCR80)
* [Configure and run customized frameworks](https://youtu.be/12Sanq_rEhs)
* Customize control configurations: 
  - [Kubescape CLI](https://youtu.be/955psg6TVu4) 
  - [ARMO Platform](https://youtu.be/lIMVSVhH33o)
