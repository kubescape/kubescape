<img src="docs/kubescape.png" width="300" alt="logo" align="center">

Kubescape is the first tool for testing if Kubernetes is deployed securely as defined in [Kubernetes Hardening Guidance by to NSA and CISA](https://www.nsa.gov/News-Features/Feature-Stories/Article-View/Article/2716980/nsa-cisa-release-kubernetes-hardening-guidance/)
Tests are configured with YAML files, making this tool easy to update as test specifications evolve.

<img src="docs/using-mov.gif">

# TL;DR
## Installation
To install the tool locally, run this:

`curl -s https://raw.githubusercontent.com/armosec/kubescape/master/install.sh | /bin/bash`

<img src="docs/install.jpeg">

## Run
To get a fast check of the security posture of your Kubernetes cluster, run this:

`kubescape scan framework nsa`

<img src="docs/run.jpeg">


# Status
[![build](https://github.com/armosec/kubescape/actions/workflows/build.yaml/badge.svg)](https://github.com/armosec/kubescape/actions/workflows/build.yaml)

# How to build 
`go mod tidy && go build -o kubescape` :zany_face:

# Under the hood

## Tests
Kubescape is running the following tests according to what is defined by [Kubernetes Hardening Guidance by to NSA and CISA](https://www.nsa.gov/News-Features/Feature-Stories/Article-View/Article/2716980/nsa-cisa-release-kubernetes-hardening-guidance/)
* Non-root containers
* Immutable container filesystem 
* Building secure container images
* Privileged containers 
* hostPID, hostIPC privileges
* hostNetwork access
* allowedHostPaths field
* Protecting pod service account tokens
* Pods in kube-system and kube-public
* Resource policies
* Control plane hardening 
* Encrypted secrets 
* Anonymous Requests


## Technology
Kubescape based on OPA engine: https://github.com/open-policy-agent/opa and ARMO's posture controls. 

The tools retrieves Kubernetes objects from the API server and runs a set of [regos snippets](https://www.openpolicyagent.org/docs/latest/policy-language/) developed by [ARMO](https://www.armosec.io/). 

The results by default printed in a pretty "console friendly" manner, but they can be retrieved in JSON format for further processing.
