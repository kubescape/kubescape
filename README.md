<img src="docs/kubescape.png" width="300" alt="logo" align="center">

kubescape is a tool for testing Kubernetes clusters against industry accepted security standards and recomendations like:
* NSA hardening for Kubernetes operators [see here](https://media.defense.gov/2021/Aug/03/2002820425/-1/-1/1/CTR_KUBERNETES%20HARDENING%20GUIDANCE.PDF)
* MITRE threat matrix for Kubernetes [see here](https://www.microsoft.com/security/blog/2020/04/02/attack-matrix-kubernetes/)

# TL;DR
To get a fast check of the security posture of your Kubernetes cluster run this:

`curl -s https://raw.githubusercontent.com/armosec/kubescape/master/install.sh | /bin/bash`

<img src="docs/install.jpeg">


# Status
[![build](https://github.com/armosec/kubescape/actions/workflows/build.yaml/badge.svg)](https://github.com/armosec/kubescape/actions/workflows/build.yaml)
