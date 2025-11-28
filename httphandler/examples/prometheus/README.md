# Prometheus Integration

> **Note**: The Prometheus integration documentation has moved to the Kubescape Helm Charts repository.

## Current Documentation

For the latest Prometheus integration guide, please visit:

**[Kubescape Prometheus Integration →](https://github.com/kubescape/helm-charts/blob/main/charts/kubescape-operator/README.md#kubescape-prometheus-integration)**

## Quick Overview

The Kubescape Operator exposes Prometheus metrics for monitoring your cluster's security posture.

### Features

- Compliance score metrics per framework
- Control pass/fail counts
- Vulnerability counts by severity
- Resource scan statistics

### Installation with Prometheus Support

```bash
helm repo add kubescape https://kubescape.github.io/helm-charts/
helm repo update

helm upgrade --install kubescape kubescape/kubescape-operator \
  --namespace kubescape \
  --create-namespace \
  --set capabilities.prometheusExporter=enable
```

### Available Metrics

| Metric | Description |
|--------|-------------|
| `kubescape_compliance_score` | Compliance score per framework (0-100) |
| `kubescape_controls_passed` | Number of passed controls |
| `kubescape_controls_failed` | Number of failed controls |
| `kubescape_resources_scanned` | Total resources scanned |
| `kubescape_vulnerabilities_total` | Vulnerabilities by severity |

### ServiceMonitor (for Prometheus Operator)

If you're using the Prometheus Operator, the Helm chart can create a ServiceMonitor:

```bash
helm upgrade --install kubescape kubescape/kubescape-operator \
  --namespace kubescape \
  --create-namespace \
  --set capabilities.prometheusExporter=enable \
  --set serviceMonitor.enabled=true
```

### Grafana Dashboard

A pre-built Grafana dashboard is available for visualizing Kubescape metrics:

- [Kubescape Grafana Dashboard](https://grafana.com/grafana/dashboards/18183-kubescape/)

---

## Related Documentation

- [Kubescape Operator Installation](https://kubescape.io/docs/install-operator/)
- [Helm Charts Repository](https://github.com/kubescape/helm-charts)
- [HTTP Handler API](../../README.md)
- [Microservice Deployment](../microservice/README.md)