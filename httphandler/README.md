# Kubescape HTTP Handler Package

> This is a beta version, we might make some changes before publishing the official Prometheus support

Running `kubescape` will start up a webserver on port `8080` which will serve the following paths: 

* POST `/v1/scan` - Trigger a kubescape scan. The server will return an ID and will execute the scanning asynchronously 
* * `wait`: scan synchronously (return results and not ID). Use only in small clusters are with an increased timeout
* * `keep`: Do not delete results from local storage after returning
* GET `/v1/results` -  Request kubescape scan results
* * query `id=<string>` -> ID returned when triggering the scan action. If empty will return latest results
* * query `keep` -> Do not delete results from local storage after returning
* DELETE `/v1/results` - Delete kubescape scan results from storage. If empty will delete latest results
* * query `id=<string>`: Delete ID of specific results 
* * query `all`: Delete all cached results
* GET/POST `/v1/metrics` - will trigger cluster scan. will respond with prometheus metrics once they have been scanned. This will respond 503 if the scan failed.
* `/livez` - will respond 200 is server is alive
* `/readyz` - will respond 200 if server can receive requests 

## Trigger Kubescape scan

POST /v1/results
body:
```
{
    "format": <str>,               // results format [default: json] (same as 'kubescape scan --format')
    "excludedNamespaces": [<str>], // list of namespaces to exclude (same as 'kubescape scan --excluded-namespaces')
    "includeNamespaces": [<str>],  // list of namespaces to include (same as 'kubescape scan --include-namespaces')
    "useCachedArtifacts"`: <bool>, // use the cached artifacts instead of downloading (offline support)
    "submit": <bool>,              // submit results to Kubescape cloud (same as 'kubescape scan --submit')
    "hostScanner": <bool>,         // deploy kubescape K8s host-scanner DaemonSet in the scanned cluster (same as 'kubescape scan --enable-host-scan')
    "keepLocal": <bool>,           // do not submit results to Kubescape cloud (same as 'kubescape scan --keep-local')
    "account": <str>,              // account ID (same as 'kubescape scan --account')
    "targetType": <str>,           // framework/control
    "targetNames": [<str>]         // names. e.g. when targetType==framework, targetNames=["nsa", "mitre"]
}
```

#### Default scan  

1. Trigger kubescape scan
  ```bash
  curl --header "Content-Type: application/json" --request POST --data '{"hostScanner":true}' http://127.0.0.1:8080/v1/scan -o scan_id
  ```

2. Get kubescape scan results
  ```bash
  curl --request GET http://127.0.0.1:8080/v1/results?id=$(cat scan_id)
  ```

#### Scan single namespace with a specific framework
```bash
curl --header "Content-Type: application/json" \
  --request POST \
  --data '{"hostScanner":true, "submit":true, "includeNamespaces": ["ks-scanner"], "targetType": "framework", "targetNames": ["nsa"] }' \
  http://127.0.0.1:8080/v1/scan
```
## Examples

* [Prometheus](examples/prometheus/README.md)
* [Microservice](examples/microservice/README.md)


## Supported environment variables

* `KS_ACCOUNT`: Account ID
* `KS_SUBMIT`: Submit the results to Kubescape SaaS version
* `KS_EXCLUDE_NAMESPACES`: List of namespaces to exclude, e.g. `KS_EXCLUDE_NAMESPACES=kube-system,kube-public`
* `KS_INCLUDE_NAMESPACES`: List of namespaces to include, rest of the namespaces will be ignored. e.g. `KS_INCLUDE_NAMESPACES=dev,prod`
* `KS_HOST_SCAN_YAML`: Full path to the host scanner YAML
* `KS_FORMAT`: Output file format. default is json
* `KS_ENABLE_HOST_SCANNER`: Enable the host scanner feature
* `KS_DOWNLOAD_ARTIFACTS`: Download the artifacts every scan
