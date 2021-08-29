<img src="docs/kubescape.png" width="300" alt="logo" align="center">

[![build](https://github.com/armosec/kubescape/actions/workflows/build.yaml/badge.svg)](https://github.com/armosec/kubescape/actions/workflows/build.yaml)
[![Github All Releases](https://img.shields.io/github/downloads/armosec/kubescape/total.svg)]()
[![Go Report Card](https://goreportcard.com/badge/github.com/armosec/kubescape)](https://goreportcard.com/report/github.com/armosec/kubescape)

Kubescape is the first tool for testing if Kubernetes is deployed securely as defined in [Kubernetes Hardening Guidance by NSA and CISA](https://www.nsa.gov/News-Features/Feature-Stories/Article-View/Article/2716980/nsa-cisa-release-kubernetes-hardening-guidance/)

Use Kubescape to test clusters or scan single YAML files and integrate it to your processes. 

<img src="docs/demo.gif">

# TL;DR
## Install & Run

### Install:
```
curl -s https://raw.githubusercontent.com/armosec/kubescape/master/install.sh | /bin/bash
```

### Run:
```
kubescape scan framework nsa --exclude-namespaces kube-system,kube-public
```

If you wish to scan all namespaces in your cluster, remove the `--exclude-namespaces` flag.

<img src="docs/summary.png">



## Usage & Examples

### Pre-Deployment Testing
Check your YAML files before you're deploying, simply add them at the end of command line:
```
kubescape scan framework nsa *.yaml
```

### Integration with other tools

Kubescape can produce output fitting for later processing:
* JSON (`-o json`)
* JUnit XML (`-o junit`)

### Examples

* Scan a running Kubernetes cluster with [`nsa`](https://www.nsa.gov/News-Features/Feature-Stories/Article-View/Article/2716980/nsa-cisa-release-kubernetes-hardening-guidance/) framework
```
kubescape scan framework nsa --exclude-namespaces kube-system,kube-public
```

* Scan a running Kubernetes cluster with [`mitre`](https://www.microsoft.com/security/blog/2020/04/02/attack-matrix-kubernetes/) framework
```
kubescape scan framework mitre --exclude-namespaces kube-system,kube-public
```


* Scan local `yaml`/`json` files
```
kubescape scan framework nsa examples/online-boutique/*
```


* Scan `yaml`/`json` files from url
```
kubescape scan framework nsa https://raw.githubusercontent.com/GoogleCloudPlatform/microservices-demo/master/release/kubernetes-manifests.yaml
```

* Output in `json` format
```
kubescape scan framework nsa --exclude-namespaces kube-system,kube-public --silence -o json > results.json
```

* Output in `junit xml` format
```
kubescape scan framework nsa --exclude-namespaces kube-system,kube-public --silence -o junit > results.xml
```

# How to build 

Note: development (and the release process) is done with Go `1.16`

1. Clone Project
```
git clone git@github.com:armosec/kubescape.git kubescape && cd "$_"
```

2. Build
```
go mod tidy && go build -o kubescape .
```

3. Run
```
./kubescape scan framework nsa --exclude-namespaces kube-system,kube-public
```

4. Enjoy :zany_face:

# Under the hood

## Tests
Kubescape is running the following tests according to what is defined by [Kubernetes Hardening Guidance by NSA and CISA](https://www.nsa.gov/News-Features/Feature-Stories/Article-View/Article/2716980/nsa-cisa-release-kubernetes-hardening-guidance/)
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


## Technology
Kubescape based on OPA engine: https://github.com/open-policy-agent/opa and ARMO's posture controls. 

The tools retrieves Kubernetes objects from the API server and runs a set of [regos snippets](https://www.openpolicyagent.org/docs/latest/policy-language/) developed by [ARMO](https://www.armosec.io/). 

The results by default printed in a pretty "console friendly" manner, but they can be retrieved in JSON format for further processing.

Kubescape is an open source project, we welcome your feedback and ideas for improvement. We’re also aiming to collaborate with the Kubernetes community to help make the tests themselves more robust and complete as Kubernetes develops.


