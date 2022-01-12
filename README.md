<img src="docs/kubescape.png" width="300" alt="logo" align="center">

[![build](https://github.com/armosec/kubescape/actions/workflows/build.yaml/badge.svg)](https://github.com/armosec/kubescape/actions/workflows/build.yaml)
[![Go Report Card](https://goreportcard.com/badge/github.com/armosec/kubescape)](https://goreportcard.com/report/github.com/armosec/kubescape)

Kubescape is the first open-source tool for testing if Kubernetes is deployed securely according to multiple frameworks:
regulatory, customized company policies and DevSecOps best practices, such as the  [NSA-CISA](https://www.armosec.io/blog/kubernetes-hardening-guidance-summary-by-armo) and the [MITRE ATT&CK®](https://www.microsoft.com/security/blog/2021/03/23/secure-containerized-environments-with-updated-threat-matrix-for-kubernetes/) .  
Kubescape scans K8s clusters, YAML files, and HELM charts, and detect misconfigurations and software vulnerabilities at early stages of the CI/CD pipeline and provides a risk score instantly and risk trends over time.
Kubescape integrates natively with other DevOps tools, including Jenkins, CircleCI and Github workflows.

</br>

<img src="docs/demo.gif">

# TL;DR
## Install:
```
curl -s https://raw.githubusercontent.com/armosec/kubescape/master/install.sh | /bin/bash
```

[Install on windows](#install-on-windows)

[Install on macOS](#install-on-macos)

## Run:
```
kubescape scan --submit
```

<img src="docs/summary.png">

</br>

> Kubescape is an open source project, we welcome your feedback and ideas for improvement. We’re also aiming to collaborate with the Kubernetes community to help make the tests themselves more robust and complete as Kubernetes develops.

</br>

### Click [👍](https://github.com/armosec/kubescape/stargazers) if you want us to continue to develop and improve Kubescape 😀

</br>


# Being part of the team

We invite you to our team! We are excited about this project and want to return the love we get.

Want to contribute? Want to discuss something? Have an issue?

* Open a issue, we are trying to respond within 48 hours
* [Join us](https://armosec.github.io/kubescape/) in a discussion on our discord server!

[<img src="docs/discord-banner.png" width="100" alt="logo" align="center">](https://armosec.github.io/kubescape/)


# Options and examples

## Tutorials

* [Overview](https://youtu.be/wdBkt_0Qhbg)
* [Scanning Kubernetes YAML files](https://youtu.be/Ox6DaR7_4ZI)
* [Scan Kubescape on an air-gapped environment (offline support)](https://youtu.be/IGXL9s37smM)
* [Managing exceptions in the Kubescape SaaS version](https://youtu.be/OzpvxGmCR80)

## Install on Windows

**Requires powershell v5.0+**

``` powershell
iwr -useb https://raw.githubusercontent.com/armosec/kubescape/master/install.ps1 | iex
```

Note: if you get an error you might need to change the execution policy (i.e. enable Powershell) with

``` powershell
Set-ExecutionPolicy RemoteSigned -scope CurrentUser
```

## Install on macOS

1. ```
    brew tap armosec/kubescape
    ```
2. ```
    brew install kubescape
    ```

## Flags

| flag                        | default                   | description                                                                                                                                                                                                                                                                                                          | options                          |
|-----------------------------|---------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------|
| `-e`/`--exclude-namespaces` | Scan all namespaces       | Namespaces to exclude from scanning. Recommended to exclude `kube-system` and `kube-public` namespaces                                                                                                                                                                                                               |                                              |
| `--include-namespaces`      | Scan all namespaces       | Scan specific namespaces                                                                                                                            |                                              |
| `-s`/`--silent`             | Display progress messages | Silent progress messages                                                                                                                                                                                                                                                                                             |                                              |
| `-t`/`--fail-threshold`     | `100` (do not fail)         | fail command (return exit code 1) if result is above threshold                                                                                                                                                                                                                                                       | `0` -> `100`                                 |
| `-f`/`--format`             | `pretty-printer`          | Output format                                                                                                                                                                                                                                                                                                        | `pretty-printer`/`json`/`junit`/`prometheus` |
| `-o`/`--output`             | print to stdout           | Save scan result in file                                                                                                                                                                                                                                                                                             |                                              |
| `--use-from`                |                           | Load local framework object from specified path. If not used will download latest                                                                                                                                                                                                                                    |                                              |
| `--use-default`             | `false`                   | Load local framework object from default path. If not used will download latest                                                                                                                                                                                                                                      | `true`/`false`                               |
| `--exceptions`              |                           | Path to an [exceptions obj](examples/exceptions.json). If not set will download exceptions from Armo management portal                                                                                                                                                                                               |                                              |
| `--submit`                  | `false`                   | If set, Kubescape will send the scan results to Armo management portal where you can see the results in a user-friendly UI, choose your preferred compliance framework, check risk results history and trends, manage exceptions, get remediation recommendations and much more. By default the results are not sent | `true`/`false`                               |
| `--keep-local`              | `false`                   | Kubescape will not send scan results to Armo management portal. Use this flag if you ran with the `--submit` flag in the past and you do not want to submit your current scan results                                                                                                                                | `true`/`false`                               |
| `--account`                 |                           | Armo portal account ID. Default will load account ID from configMap or config file                                                                                                                                                                                                                                   |                                              |
| `--kube-context`                 |        current-context               |  Cluster context to scan                                                                                                                                                                                                                              |                                              |
| `--verbose`                 | `false`                   | Display all of the input resources and not only failed resources                                                                                                                                                                                                                                                     | `true`/`false`                               |


## Usage & Examples

### Examples

#### Scan a running Kubernetes cluster with [`nsa`](https://www.nsa.gov/Press-Room/News-Highlights/Article/Article/2716980/nsa-cisa-release-kubernetes-hardening-guidance/) framework and submit results to the [Kubescape SaaS version](https://portal.armo.cloud/)
```
kubescape scan framework nsa --submit
```


#### Scan a running Kubernetes cluster with [`MITRE ATT&CK®`](https://www.microsoft.com/security/blog/2021/03/23/secure-containerized-environments-with-updated-threat-matrix-for-kubernetes/) framework and submit results to the [Kubescape SaaS version](https://portal.armo.cloud/)
```
kubescape scan framework mitre --submit
```


#### Scan a running Kubernetes cluster with a specific control using the control name or control ID. [List of controls](https://hub.armo.cloud/docs/controls) 
```
kubescape scan control "Privileged container"
```

#### Scan specific namespaces
```
kubescape scan framework nsa --include-namespaces development,staging,production
```

#### Scan cluster and exclude some namespaces
```
kubescape scan framework nsa --exclude-namespaces kube-system,kube-public
```

#### Scan local `yaml`/`json` files before deploying. [Take a look at the demonstration](https://youtu.be/Ox6DaR7_4ZI)
```
kubescape scan framework nsa *.yaml
```

#### Scan kubernetes manifest files from a public github repository 
```
kubescape scan framework nsa https://github.com/armosec/kubescape
```

#### Display all scanned resources (including the resources who passed) 
```
kubescape scan framework nsa --verbose
```

#### Output in `json` format
```
kubescape scan framework nsa --format json --output results.json
```

#### Output in `junit xml` format
```
kubescape scan framework nsa --format junit --output results.xml
```

#### Output in `prometheus` metrics format - Contributed by [@Joibel](https://github.com/Joibel)
```
kubescape scan framework nsa --format prometheus
```

#### Scan with exceptions, objects with exceptions will be presented as `exclude` and not `fail`
[Full documentation](examples/exceptions/README.md)
```
kubescape scan framework nsa --exceptions examples/exceptions/exclude-kube-namespaces.json
```

#### Scan Helm charts - Render the helm chart using [`helm template`](https://helm.sh/docs/helm/helm_template/) and pass to stdout
```
helm template [NAME] [CHART] [flags] --dry-run | kubescape scan framework nsa -
```

e.g.
```
helm template bitnami/mysql --generate-name --dry-run | kubescape scan framework nsa -
```


### Offline Support

[Video tutorial](https://youtu.be/IGXL9s37smM)

It is possible to run Kubescape offline!

First download the framework and then scan with `--use-from` flag

1. Download and save in file, if file name not specified, will store save to `~/.kubescape/<framework name>.json`
```
kubescape download framework nsa --output nsa.json
```

2. Scan using the downloaded framework
```
kubescape scan framework nsa --use-from nsa.json
```


## Scan Periodically using Helm - Contributed by [@yonahd](https://github.com/yonahd)  
 
You can scan your cluster periodically by adding a `CronJob` that will repeatedly trigger kubescape

```
helm install kubescape examples/helm_chart/
```

## Scan using docker image

Official Docker image `quay.io/armosec/kubescape`

```
docker run -v "$(pwd)/example.yaml:/app/example.yaml  quay.io/armosec/kubescape scan framework nsa /app/example.yaml
```

# Submit data manually

Use the `submit` command if you wish to submit data manually

## Submit scan results manually

First, scan your cluster using the `json` format flag: `kubescape scan framework <name> --format json --output path/to/results.json`.

Now you can submit the results to the Kubaescape SaaS version -
```
kubescape submit results path/to/results.json
```
# How to build

## Build using python (3.7^) script

Kubescape can be built using:

``` sh
python build.py
```

Note: In order to built using the above script, one must set the environment
variables in this script:

+ RELEASE
+ ArmoBEServer
+ ArmoERServer
+ ArmoWebsite


## Build using go

Note: development (and the release process) is done with Go `1.17`

1. Clone Project
```
git clone https://github.com/armosec/kubescape.git kubescape && cd "$_"
```

2. Build
```
go build -o kubescape .
```

3. Run
```
./kubescape scan framework nsa
```

4. Enjoy :zany_face:

## Docker Build

### Build your own Docker image

1. Clone Project
```
git clone https://github.com/armosec/kubescape.git kubescape && cd "$_"
```

2. Build
```
docker build -t kubescape -f build/Dockerfile .
```


# Under the hood

## Tests
Kubescape is running the following tests according to what is defined by [Kubernetes Hardening Guidance by NSA and CISA](https://www.nsa.gov/Press-Room/News-Highlights/Article/Article/2716980/nsa-cisa-release-kubernetes-hardening-guidance/)
* Non-root containers
* Immutable container filesystem
* Privileged containers
* hostPID, hostIPC privileges
* hostNetwork access
* allowedHostPaths field
* Protecting pod service account tokens
* Resource policies
* Control plane hardening
* Exposed dashboard
* Allow privilege escalation
* Applications credentials in configuration files
* Cluster-admin binding
* Exec into container
* Dangerous capabilities
* Insecure capabilities
* Linux hardening
* Ingress and Egress blocked
* Container hostPort
* Network policies
* Symlink Exchange Can Allow Host Filesystem Access (CVE-2021-25741)



## Technology
Kubescape based on OPA engine: https://github.com/open-policy-agent/opa and ARMO's posture controls.

The tools retrieves Kubernetes objects from the API server and runs a set of [regos snippets](https://www.openpolicyagent.org/docs/latest/policy-language/) developed by [ARMO](https://www.armosec.io/).

The results by default printed in a pretty "console friendly" manner, but they can be retrieved in JSON format for further processing.

Kubescape is an open source project, we welcome your feedback and ideas for improvement. We’re also aiming to collaborate with the Kubernetes community to help make the tests themselves more robust and complete as Kubernetes develops.
