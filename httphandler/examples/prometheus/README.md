# Prometheus Kubescape Integration

1. Deploy kubescape
    ```bash
    kubectl apply -f ks-deployment.yaml
    ```
    > **Note**  
    > Make sure the configurations suit your cluster (e.g. `serviceType`, etc.)

2. Deploy kube-prometheus-stack
    ```bash
    helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
    helm repo update
    kubectl create namespace prometheus
    helm install -n prometheus kube-prometheus-stack prometheus-community/kube-prometheus-stack --set prometheus.prometheusSpec.podMonitorSelectorNilUsesHelmValues=false,prometheus.prometheusSpec.serviceMonitorSelectorNilUsesHelmValues=false
    ```
3. Deploy pod monitor
    ```bash
    kubectl apply -f podmonitor.yaml
    ```
 

## Metrics

All kubescape related metrics begin with `kubescape`

> `riskScore` is the output of an algorithm calculating the risk of the vulnerability. `0` indicates there is no risk and `100` indicates highest risk. 

#### Cluster scope metrics

##### Overall risk score
```
# Overall riskScore of the scan
kubescape_cluster_riskScore{} <risk score>
```

###### Overall resources counters
```
# Number of resources that failed 
kubescape_cluster_count_resources_failed{} <counter>

# Number of resources that where skipped
kubescape_cluster_count_resources_skipped{} <counter>

# Number of resources that passed
kubescape_cluster_count_resources_passed{} <counter>
```

###### Overall controls counters
```
# Number of controls that failed 
kubescape_cluster_count_controls_failed{} <counter>

# Number of controls that where skipped 
kubescape_cluster_count_controls_skipped{} <counter>

# Number of controls that passed
kubescape_cluster_count_controls_passed{} <counter>
```

#### Frameworks metrics

##### Frameworks risk score
```
kubescape_framework_riskScore{name="<framework name>"} <risk score>
```

###### Frameworks resources counters

```
# Number of resources that failed 
kubescape_framework_count_resources_failed{} <counter>

# Number of resources that where skipped
kubescape_framework_count_resources_skipped{} <counter>

# Number of resources that passed
kubescape_framework_count_resources_passed{} <counter>
``` 
###### Frameworks controls counters

```
# Number of controls that failed 
kubescape_framework_count_controls_failed{name="<framework name>"} <counter>

# Number of controls that where skipped 
kubescape_framework_count_controls_skipped{name="<framework name>"} <counter>

# Number of controls that passed
kubescape_framework_count_controls_passed{name="<framework name>"} <counter>
```

#### Controls metrics

##### Controls risk score

```
kubescape_control_riskScore{name="<control name>",url="<docs url>",severity="<control severity>"} <risk score>
```

###### Controls resources counters

```
# Number of resources that failed 
kubescape_control_count_resources_failed{name="<control name>",url="<docs url>",severity="<control severity>"} <counter>

# Number of resources that where skipped
kubescape_control_count_resources_skipped{name="<control name>",url="<docs url>",severity="<control severity>"} <counter>

# Number of resources that passed
kubescape_control_count_resources_passed{name="<control name>",url="<docs url>",severity="<control severity>"} <counter>
```

 