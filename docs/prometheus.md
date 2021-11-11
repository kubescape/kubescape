# Using kubescape with prometheus

This is a complimentary way of securing your cluster for existing deployments, and for finding violations when the rules have changed after deployment. Alertmanager can then inform you of new violations found because the frameworks have improved.

Running kubescape in CI should be also deployed.

You can also use this to take a cluster with problems and easilly pick which areas to tackle and fix and see those fixes getting solved automatically - perhaps tackling all of one type of violation at a time rather than per application/namespace.

## Metrics server

Running "kubescape metrics framework nsa" will start up a webserver on port 80 which will serve the following paths

/metrics - will respond with prometheus metrics once they have been scanned. This will respond 503 before scanning completes or if the last scan failed.
/livez - will respond 204 OK every time
/readyz - will respond 204 once metrics are available

| flag                        | default             | description                                                                                                            |
|-----------------------------|---------------------|------------------------------------------------------------------------------------------------------------------------|
| `-p`/`--port`               | 80                  | Port number to serve on.                                                                                               |
| `-i`/`--interval`           | 300                 | Interval between scans in seconds. If the scan takes longer than this, then the scans will be continous.               |
| `-u`/`--update`             | 14400               | Interval between attempts to download new scan rules in seconds. Default is 4 hours.                                   |
| `-e`/`--exclude-namespaces` | Scan all namespaces | Namespaces to exclude from scanning. Recommended to exclude `kube-system` and `kube-public` namespaces                 |
| `--exceptions`              |                     | Path to an [exceptions obj](examples/exceptions.json). If not set will download exceptions from Armo management portal |

Note: there is no https support at this time

The metrics command does not serve other formats of kubescape output.

## Installation into kubernetes

This way of running kubescape is designed to be used inside kubernetes, and this documents how to use it with the [prometheus operator](https://prometheus-operator.dev/). The author recommends [kube-prometheus-stack](https://github.com/prometheus-community/helm-charts/blob/main/charts/kube-prometheus-stack/README.md) as a quick way of getting started. It should be possible use it in other ways with prometheus.

The files in [examples/kubernetes](../examples/kubernetes) will deploy one instance of kubescape to run the nsa framework on your cluster. 

### [namespace.yaml](../examples/kubernetes/namespace.yaml)
Creates as separate namespace to run kubescape in.

### [clusterrole.yaml](../examples/kubernetes/clusterrole.yaml)
Creates a role that allows kubescape to read all resources in the cluster - necessary for it to operate.

### [serviceaccount.yaml](../examples/kubernetes/serviceaccount.yaml)
Creates an account for kubescape to run as.

### [clusterrolebinding.yaml](../examples/kubernetes/clusterrolebinding.yaml)
Binds the cluster roles to the service account so that kubescape can read all resources.

### [deployment.yaml](../examples/kubernetes/deployment.yaml)
Creates a pod running kubescape.

*NOTE* You can configure the arguments to kubescape here by changing args. This example deployment runs the nsa framework against everything in the cluster. You may well wish to change this. You may well wish to run scans less frequently to save CPU resources in your cluster, especially once you have fixed most violations, you can do this by adding "-i", "1800" to set it to every 30 minutes for example.

### [service.yaml](../examples/kubernetes/service.yaml)
Creates a service to allow prometheus to access the http port on the kubescape metrics server.

### [servicemonitor.yaml](../examples/kubernetes/servicemonitor.yaml)
This tells preometheus to scrape kubescape every 'interval' seconds. Note that scraping kubescape at different frequencies does *not* change how often kubescape scans the cluster.

In order for this to be deployed to the kubescape namespace instead of the prometheus namespace you'll need to allow the prometheus operator to scan for service monitors in all namespaces. With [kube-prometheus-stack](https://github.com/prometheus-community/helm-charts/blob/main/charts/kube-prometheus-stack/README.md) you set prometheus.prometheusSpec.serviceMonitorSelectorNilUsesHelmValues to false

### [networkpolicy.yaml](../examples/kubernetes/networkpolicy.yaml)

If you don't have a valid networkpolicy the nsa framework will tell you that kubescape is violating. You almost certainly will have to change the example network policy to make the labels match those for your own prometheus. If you don't prometheus will be unable to scrape kubescape, and you won't get /metrics log messages in kubescape's log.

I'd suggest not deploying this object to start with until you have the rest working.

### [prometheusrule.yaml](../examples/kubernetes/prometheusrule.yaml)

Some example rules for prometheus to generate alerts when violations are found. These examples would probably want refining for your own deployment.

