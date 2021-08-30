# Kubescape Release 


## Input

### Scan a running Kubernetes cluster

* Scan your Kubernetes cluster. Ignore `kube-system` and `kube-public` namespaces
```
kubescape scan framework nsa --exclude-namespaces kube-system,kube-public
```

* Scan your Kubernetes cluster
```
kubescape scan framework nsa 
```

### Scan a local Kubernetes manifest
 
* Scan single Kubernetes manifest file <img src="new-feature.svg">
```
kubescape scan framework nsa <my-workload.yaml>
```

* Scan many Kubernetes manifest files <img src="new-feature.svg">
```
kubescape scan framework nsa <my-workload-1.yaml> <my-workload-2.yaml>
```

* Scan all Kubernetes manifest files in directory  <img src="new-feature.svg">
```
kubescape scan framework nsa *.yaml
```

* Scan Kubernetes manifest from stdout  <img src="new-feature.svg">
```
cat <my-workload.yaml> | kubescape scan framework nsa -
```


* Scan Kubernetes manifest url  <img src="new-feature.svg">
```
kubescape scan framework nsa https://raw.githubusercontent.com/GoogleCloudPlatform/microservices-demo/master/release/kubernetes-manifests.yaml
```

### Scan HELM chart

* Render the helm chart using [`helm template`](https://helm.sh/docs/helm/helm_template/) and pass to stdout <img src="new-feature.svg">
```
helm template [CHART] [flags] --generate-name --dry-run | kubescape scan framework nsa -
```

## Output formats

By default, the output is user friendly.

For the sake of automation, it is possible to receive the result in a `json` or `junit xml` format.

* Output in `json` format <img src="new-feature.svg">
```
kubescape scan framework nsa --format json --output results.json
```

* Output in `junit xml` format <img src="new-feature.svg">
```
kubescape scan framework nsa --format junit --output results.xml
```