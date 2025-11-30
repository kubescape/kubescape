# Helm Chart Examples

> ⚠️ **DEPRECATED**: This directory contains legacy Helm chart examples that are no longer maintained.

## Current Helm Charts

For the latest Kubescape Helm charts, please visit:

**[Kubescape Helm Charts Repository](https://github.com/kubescape/helm-charts)**

## Quick Install

```bash
# Add the Kubescape Helm repository
helm repo add kubescape https://kubescape.github.io/helm-charts/
helm repo update

# Install the Kubescape operator
helm upgrade --install kubescape kubescape/kubescape-operator \
  --namespace kubescape \
  --create-namespace
```

## Available Charts

| Chart | Description |
|-------|-------------|
| [kubescape-operator](https://github.com/kubescape/helm-charts/tree/main/charts/kubescape-operator) | Full Kubescape in-cluster operator |

## Documentation

- [Operator Installation Guide](https://kubescape.io/docs/install-operator/)
- [Operator Configuration Options](https://github.com/kubescape/helm-charts/blob/main/charts/kubescape-operator/README.md)
- [Prometheus Integration](https://github.com/kubescape/helm-charts/blob/main/charts/kubescape-operator/README.md#kubescape-prometheus-integration)

## Migration from Legacy Charts

If you were using the legacy `armo-helm` charts, please migrate to the new `kubescape/helm-charts` repository. The new charts provide:

- Continuous vulnerability scanning
- Configuration scanning
- Runtime threat detection (eBPF-based)
- Network policy generation
- Prometheus metrics
- And more...

See the [migration guide](https://kubescape.io/docs/install-operator/) for detailed instructions.