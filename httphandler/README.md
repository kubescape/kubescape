# Kubescape HTTP Handler Package

> This is a beta version, we might make some changes before publishing the official Prometheus support

Running `kubescape` will start up a webserver on port `8080` which will serve the following paths: 

### Trigger scan

* POST `/v1/scan` - Trigger a kubescape scan. The server will return an ID and will execute the scanning asynchronously 
* * `wait=true`: scan synchronously (return results and not ID). Use only in small clusters are with an increased timeout. default is `wait=false`
* * `keep=true`: Do not delete results from local storage after returning. default is `keep=false`

### Get results
* GET `/v1/results` -  Request kubescape scan results
* * query `id=<string>` -> ID returned when triggering the scan action. If empty will return latest results
* * query `keep=true` -> Do not delete results from local storage after returning. default is `keep=false`

### Check scanning progress status
Check the scanning status - is the scanning in progress or done. This is meant for a waiting mechanize since the API does not return the entire results object when the scanning is done

* GET `/v1/status` -  Request kubescape scan status
* * query `id=<string>` -> Check status of a specific scan. If empty will check if any scan is in progress

### Delete cached results
* DELETE `/v1/results` - Delete kubescape scan results from storage. If empty will delete latest results
* * query `id=<string>`: Delete ID of specific results 
* * query `all`: Delete all cached results

### Prometheus support API

* GET/POST `/v1/metrics` - will trigger cluster scan. will respond with prometheus metrics once they have been scanned. This will respond 503 if the scan failed.
* `/livez` - will respond 200 is server is alive
* `/readyz` - will respond 200 if server can receive requests 

## Trigger Kubescape scan

POST /v1/scan
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

Response body:
```
{
  "id": <str>,                      // scan ID
  "type": <responseType:str>,       // response object type
  "response": <object:interface>    // response payload as list of bytes
}
```

Response body types:
*  "v1results" - v1 results object
*  "id" - id string
*  "error" - error object

## API Examples
#### Default scan  

1. Trigger kubescape scan
  ```bash
  curl --header "Content-Type: application/json" --request POST --data '{"hostScanner":true, "submit": true}' http://127.0.0.1:8080/v1/scan
  ```

2. Get kubescape scan results
  ```bash
  curl --request GET http://127.0.0.1:8080/v1/results -o response.json
  ```

#### Trigger scan and wait for scan to end  

```bash
curl --header "Content-Type: application/json" --request POST --data '{"hostScanner":true, "submit": true}' http://127.0.0.1:8080/v1/scan?wait -o scan_results.json
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
