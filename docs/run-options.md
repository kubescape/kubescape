<img src="kubescape.png" width="300" alt="logo" align="center">

# More detailed look on command line arguments and options

## Simple run:
```
kubescape scan framework nsa --exclude-namespaces kube-system,kube-public
```

## Flags

| flag |  default | description | options |
| --- | --- | --- | --- |
| `-e`/`--exclude-namespaces` | Scan all namespaces | Namespaces to exclude from scanning. Recommended to exclude `kube-system` and `kube-public` namespaces |
| `-s`/`--silent` | Display progress messages | Silent progress messages |
| `-t`/`--fail-threshold` | `0` (do not fail) | fail command (return exit code 1) if result bellow threshold| `0` -> `100` |
| `-f`/`--format` | `pretty-printer` | Output format | `pretty-printer`/`json`/`junit` | 
| `-o`/`--output` | print to stdout | Save scan result in file |
| `--use-from` | | Load local framework object from specified path. If not used will download latest |
| `--use-default` | `false` | Load local framework object from default path. If not used will download latest | `true`/`false` |
| `--exceptions` | | Path to an [exceptions obj](examples/exceptions.json). If not set will download exceptions from Armo management portal |
| `--results-locally` | `false` | Kubescape sends scan results to Armo management portal to allow users to control exceptions and maintain chronological scan results. Use this flag if you do not wish to use these features | `true`/`false`|

## Usage & Examples
 
### Examples

* Scan a running Kubernetes cluster with [`nsa`](https://www.nsa.gov/News-Features/Feature-Stories/Article-View/Article/2716980/nsa-cisa-release-kubernetes-hardening-guidance/) framework
```
kubescape scan framework nsa --exclude-namespaces kube-system,kube-public
```

* Scan local `yaml`/`json` files before deploying
```
kubescape scan framework nsa *.yaml
```


* Scan `yaml`/`json` files from url 
```
kubescape scan framework nsa https://raw.githubusercontent.com/GoogleCloudPlatform/microservices-demo/master/release/kubernetes-manifests.yaml
```

* Output in `json` format 
```
kubescape scan framework nsa --exclude-namespaces kube-system,kube-public --format json --output results.json
```

* Output in `junit xml` format 
```
kubescape scan framework nsa --exclude-namespaces kube-system,kube-public --format junit --output results.xml
```

* Scan with exceptions, objects with exceptions will be presented as `warning` and not `fail`  <img src="docs/new-feature.svg">
```
kubescape scan framework nsa --exceptions examples/exceptions.json
```

### Helm Support

* Render the helm chart using [`helm template`](https://helm.sh/docs/helm/helm_template/) and pass to stdout 
```
helm template [NAME] [CHART] [flags] --dry-run | kubescape scan framework nsa -
```

for example:
```
helm template bitnami/mysql --generate-name --dry-run | kubescape scan framework nsa -
```

### Offline Support <img src="docs/new-feature.svg">

It is possible to run Kubescape offline!

First download the framework and then scan with `--use-from` flag

* Download and save in file, if file name not specified, will store save to `~/.kubescape/<framework name>.json`
```
kubescape download framework nsa --output nsa.json
```

* Scan using the downloaded framework 
```
kubescape scan framework nsa --use-from nsa.json
```

Kubescape is an open source project, we welcome your feedback and ideas for improvement. We’re also aiming to collaborate with the Kubernetes community to help make the tests themselves more robust and complete as Kubernetes develops.


