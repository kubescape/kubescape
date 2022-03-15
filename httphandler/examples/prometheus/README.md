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
    kubectl create namescape prometheus
    helm install -n prometheus kube-prometheus-stack prometheus-community/kube-prometheus-stack --set prometheus.prometheusSpec.podMonitorSelectorNilUsesHelmValues=false,prometheus.prometheusSpec.serviceMonitorSelectorNilUsesHelmValues=false
    ```
3. Deploy pod monitor
    ```bash
    kubectl apply -f podmonitor.yaml
    ```

