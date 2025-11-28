# Kubescape as a Microservice

This guide explains how to deploy Kubescape as a microservice in your Kubernetes cluster, enabling API-driven security scanning.

## Table of Contents

- [Overview](#overview)
- [Prerequisites](#prerequisites)
- [Deployment](#deployment)
- [API Usage](#api-usage)
- [Configuration](#configuration)
- [Troubleshooting](#troubleshooting)

---

## Overview

Running Kubescape as a microservice allows you to:

- Trigger security scans via REST API
- Integrate with CI/CD pipelines
- Build custom dashboards and automation
- Schedule and manage scans programmatically

---

## Prerequisites

- Kubernetes cluster with `kubectl` access
- Cluster admin permissions (for RBAC setup)
- Network access to the Kubescape service endpoint

---

## Deployment

### 1. Deploy Kubescape Microservice

```bash
kubectl apply -f ks-deployment.yaml
```

> **Note**: Review and modify `ks-deployment.yaml` to match your cluster configuration:
> - `serviceType` (ClusterIP, NodePort, LoadBalancer)
> - Namespace
> - Resource limits
> - Service account permissions

### 2. Verify Deployment

```bash
# Check pod status
kubectl get pods -l app=kubescape

# Check service
kubectl get svc kubescape
```

### 3. Access the Service

```bash
# Port-forward for local access
kubectl port-forward svc/kubescape 8080:8080

# Or get the external IP (if using LoadBalancer)
kubectl get svc kubescape -o jsonpath='{.status.loadBalancer.ingress[0].ip}'
```

---

## API Usage

### Trigger a Scan

```bash
curl --header "Content-Type: application/json" \
  --request POST \
  --data '{
    "account": "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX",
    "targetType": "framework",
    "targetNames": ["nsa", "mitre"]
  }' \
  http://127.0.0.1:8080/v1/scan
```

**Response:**
```json
{
  "id": "scan-12345",
  "type": "busy",
  "response": "scanning in progress"
}
```

### Trigger Scan and Wait for Results

```bash
curl --header "Content-Type: application/json" \
  --request POST \
  --data '{"targetType": "framework", "targetNames": ["nsa"]}' \
  "http://127.0.0.1:8080/v1/scan?wait=true" \
  -o results.json
```

### Check Scan Status

```bash
curl --request GET "http://127.0.0.1:8080/v1/status?id=scan-12345"
```

### Get Scan Results

```bash
curl --request GET "http://127.0.0.1:8080/v1/results?id=scan-12345" -o results.json
```

### Get Latest Results

```bash
curl --request GET http://127.0.0.1:8080/v1/results -o results.json
```

### Delete Cached Results

```bash
# Delete specific results
curl --request DELETE "http://127.0.0.1:8080/v1/results?id=scan-12345"

# Delete all cached results
curl --request DELETE "http://127.0.0.1:8080/v1/results?all=true"
```

---

## Configuration

### Scan Request Options

| Field | Type | Description |
|-------|------|-------------|
| `account` | string | Kubescape SaaS account ID (optional) |
| `accessKey` | string | Kubescape SaaS access key (optional) |
| `targetType` | string | `"framework"` or `"control"` |
| `targetNames` | array | List of frameworks/controls to scan |
| `excludedNamespaces` | array | Namespaces to exclude |
| `includeNamespaces` | array | Namespaces to include |
| `format` | string | Output format (default: `"json"`) |
| `keepLocal` | boolean | Don't submit results to backend |
| `useCachedArtifacts` | boolean | Use cached artifacts (offline mode) |

### Query Parameters

| Parameter | Description |
|-----------|-------------|
| `wait=true` | Wait for scan to complete (synchronous) |
| `keep=true` | Keep results in cache after returning |
| `id=<scan-id>` | Specify a particular scan ID |

### Environment Variables

Configure the microservice using environment variables in your deployment:

| Variable | Description |
|----------|-------------|
| `KS_ACCOUNT` | Default account ID |
| `KS_EXCLUDE_NAMESPACES` | Default namespaces to exclude |
| `KS_INCLUDE_NAMESPACES` | Default namespaces to include |
| `KS_FORMAT` | Default output format |
| `KS_LOGGER_LEVEL` | Log level (`debug`, `info`, `warning`, `error`) |

---

## Example Workflows

### CI/CD Integration

```bash
#!/bin/bash
# Trigger scan and wait for results
RESULT=$(curl -s --header "Content-Type: application/json" \
  --request POST \
  --data '{"targetType": "framework", "targetNames": ["nsa"]}' \
  "http://kubescape:8080/v1/scan?wait=true")

# Extract compliance score
SCORE=$(echo $RESULT | jq '.response.summaryDetails.complianceScore')

# Fail pipeline if score is below threshold
if (( $(echo "$SCORE < 80" | bc -l) )); then
  echo "Compliance score $SCORE is below threshold (80)"
  exit 1
fi
```

### Scheduled Scanning

Use a Kubernetes CronJob to trigger regular scans:

```yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: kubescape-scheduled-scan
spec:
  schedule: "0 */6 * * *"  # Every 6 hours
  jobTemplate:
    spec:
      template:
        spec:
          containers:
          - name: scanner
            image: curlimages/curl
            command:
            - /bin/sh
            - -c
            - |
              curl -X POST http://kubescape:8080/v1/scan \
                -H "Content-Type: application/json" \
                -d '{"targetType": "framework", "targetNames": ["nsa", "mitre"]}'
          restartPolicy: OnFailure
```

---

## Troubleshooting

### Service Not Accessible

```bash
# Check pod logs
kubectl logs -l app=kubescape

# Check service endpoints
kubectl get endpoints kubescape

# Verify network policies
kubectl get networkpolicies
```

### Scan Times Out

For large clusters, use asynchronous scanning:

```bash
# Trigger scan (returns immediately)
curl -X POST http://127.0.0.1:8080/v1/scan \
  -H "Content-Type: application/json" \
  -d '{"targetType": "framework", "targetNames": ["nsa"]}'

# Poll for status
while true; do
  STATUS=$(curl -s http://127.0.0.1:8080/v1/status | jq -r '.type')
  if [ "$STATUS" != "busy" ]; then
    break
  fi
  sleep 10
done

# Get results
curl http://127.0.0.1:8080/v1/results -o results.json
```

### Permission Errors

Ensure the service account has sufficient RBAC permissions to read cluster resources.

---

## Related Documentation

- [HTTP Handler API Reference](../../README.md)
- [Kubescape CLI Reference](../../../docs/cli-reference.md)
- [Prometheus Integration](../prometheus/README.md)
- [Getting Started Guide](../../../docs/getting-started.md)