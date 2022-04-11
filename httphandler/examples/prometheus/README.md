# Prometheus Kubescape Integration

1. Deploy kubescape
    ```bash
    kubectl apply -f ks-deployment.yaml
    ```
    > **NOTE** Make sure the configurations suit your cluster (e.g. `serviceType`, etc.)

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

> `riskScore` is the output of an algorithm calculating the risk of the vulinrability. `0` indicates there is no risk and `100` indicates highest risk. 

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

# Number of resources that where excluded
kubescape_cluster_count_resources_excluded{} <counter>

# Number of resources that passed
kubescape_cluster_count_resources_passed{} <counter>
```

###### Overall controls counters
```
# Number of controls that failed 
kubescape_cluster_count_controls_failed{} <counter>

# Number of controls that where excluded 
kubescape_cluster_count_controls_excluded{} <counter>

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

# Number of resources that where excluded
kubescape_framework_count_resources_excluded{} <counter>

# Number of resources that passed
kubescape_framework_count_resources_passed{} <counter>
``` 
###### Frameworks controls counters

```
# Number of controls that failed 
kubescape_framework_count_controls_failed{name="<framework name>"} <counter>

# Number of controls that where excluded 
kubescape_framework_count_controls_excluded{name="<framework name>"} <counter>

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

# Number of resources that where excluded
kubescape_control_count_resources_excluded{name="<control name>",url="<docs url>",severity="<control severity>"} <counter>

# Number of resources that passed
kubescape_control_count_resources_passed{name="<control name>",url="<docs url>",severity="<control severity>"} <counter>
```

#### Resources metrics
The resources metrics give you the ability to prioritize fixing the resources by the number of controls that failed 

```
# Number of controls that failed for this particular resource
kubescape_resource_count_controls_failed{apiVersion="<>",kind="<>",namespace="<>",name="<>"} <counter>

# Number of controls that where excluded for this particular resource
kubescape_resource_count_controls_excluded{apiVersion="<>",kind="<>",namespace="<>",name="<>"} <counter>
```