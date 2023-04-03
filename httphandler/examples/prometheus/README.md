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

> `complianceScore` is how compliant you are, where `100` indicates complete compliance and `0` means you are not compliant at all. 

#### Cluster scope metrics

##### Overall compliance score
```
# Overall complianceScore of the scan
kubescape_cluster_complianceScore{} <compliance score>
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

##### Frameworks compliance score
```
kubescape_framework_complianceScore{name="<framework name>"} <compliance score>
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

##### Controls compliance score

```
kubescape_control_complianceScore{name="<control name>",url="<docs url>",severity="<control severity>"} <compliance score>
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

 