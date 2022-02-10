# Using kubescape with prometheus

> This is a beta version, we might make some changes before publishing the official Prometheus support

**Set environment `KS_RUN_PROMETHEUS_SERVER=true`**

Running `kubescape` will start up a webserver on port `8080` which will serve the following paths: 

* `/metrics` - will trigger cluster scan (equivalent to `kubescape scan --format prometheus`) and will respond with prometheus metrics once they have been scanned. This will respond 503 if the scan failed.
* `/livez` - will respond 204 OK every time
* `/readyz` - will respond 204 once metrics are available, will respond 503 if no metrics are available

## Installation into kubernetes

The [yaml](ks-prometheus-support.yaml) file will deploy one instance of kubescape (with all relevant dependencies) to run on your cluster

**NOTE** Make sure the configurations suit your cluster (e.g. `serviceType`, namespace, etc.)