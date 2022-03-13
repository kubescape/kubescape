# Kubescape HTTP Handler Package

> This is a beta version, we might make some changes before publishing the official Prometheus support

**Set environment `KS_MICROSERVICE=true`**

Running `kubescape` will start up a webserver on port `8080` which will serve the following paths: 

* POST `/v1/scan` - Trigger a kubescape scan. The server will return an ID and will execute the scanning asynchronously 
* * `synchronously`: scan synchronously (return results and not ID). Use only in small clusters are with an increased timeout
* GET `/v1/results` -  Request kubescape scan results
* * query `id=<string>` -> ID returned when triggering the scan action. If empty will return latest results
* * query `remove` -> Remove results from storage after reading the results
* DELETE `/v1/results` - Delete kubescape scan results from storage If empty will delete latest results
* * query `id=<string>`: Delete ID of specific results 
* * query `all`: Delete all cached results
* GET/POST `/metrics` - will trigger cluster scan. will respond with prometheus metrics once they have been scanned. This will respond 503 if the scan failed.
* `/livez` - will respond 200 is server is alive
* `/readyz` - will respond 200 if server can receive requests 

## Trigger Kubescape scan

POST /v1/results
body:
```json

```

e.g.:

```bash
curl --header "Content-Type: application/json" \
  --request POST \
  --data '{"account":"42ec914f-74e6-4bcb-8e69-5edd819d9b15","hostSensor":true}' \
  http://127.0.0.1:5000/v1/scan
```
## Installation into kubernetes

The [yaml](ks-prometheus-support.yaml) file will deploy one instance of kubescape (with all relevant dependencies) to run on your cluster

**NOTE** Make sure the configurations suit your cluster (e.g. `serviceType`, namespace, etc.)