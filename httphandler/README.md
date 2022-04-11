# Kubescape HTTP Handler Package

> This is a beta version, we might make some changes before publishing the official Prometheus support

Running `kubescape` will start up a webserver on port `8080` which will serve the following paths: 

* POST `/v1/scan` - Trigger a kubescape scan. The server will return an ID and will execute the scanning asynchronously 
* * `wait`: scan synchronously (return results and not ID). Use only in small clusters are with an increased timeout
* GET `/v1/results` -  Request kubescape scan results
* * query `id=<string>` -> ID returned when triggering the scan action. ~If empty will return latest results~ (not supported)
* * query `remove` -> Remove results from storage after reading the results
* DELETE `/v1/results` - Delete kubescape scan results from storage. ~If empty will delete latest results~ (not supported)
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
    "excludedNamespaces": <[]str>, // list of namespaces to exclude (same as 'kubescape scan --excluded-namespaces')
    "includeNamespaces": <[]str>,  // list of namespaces to include (same as 'kubescape scan --include-namespaces')
    "useCachedArtifacts"`: <bool>, // use the cached artifacts instead of downloading (offline support)
    "submit": <bool>,              // submit results to Kubescape cloud (same as 'kubescape scan --submit')
    "hostScanner": <bool>,         // deploy kubescape K8s host-scanner DaemonSet in the scanned cluster (same as 'kubescape scan --enable-host-scan')
    "keepLocal": <bool>,           // do not submit results to Kubescape cloud (same as 'kubescape scan --keep-local')
    "account": <str>               // account ID (same as 'kubescape scan --account')
}
```

e.g.:

```bash
curl --header "Content-Type: application/json" \
  --request POST \
  --data '{"hostScanner":true, "submit":true}' \
  http://127.0.0.1:8080/v1/scan
```
## Examples

* [Prometheus](examples/prometheus/README.md)
* [Microservice](examples/microservice/README.md)
