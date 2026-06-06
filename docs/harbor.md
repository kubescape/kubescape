# Harbor Integration

This guide explains how to integrate Kubescape with [Harbor](https://goharbor.io), the open-source container registry. The integration uses the [harbor-scanner-kubescape](https://github.com/Onyx2406/harbor-scanner-kubescape) adapter, which implements the [Harbor Pluggable Scanner API v1.2](https://github.com/goharbor/pluggable-scanner-spec) and allows Harbor to use Kubescape as an alternative scanner to Trivy and Clair.

> **Note:** The Harbor scanner adapter is currently pending acceptance by the Harbor project. Once accepted, it will be available as an official pluggable scanner in Harbor's scanner registry.

## Prerequisites

- A running Harbor instance (v2.0 or later)
- A Kubernetes cluster with the Kubescape operator installed, including the `kubevuln` component
- Helm 3
- `kubectl` configured to access your cluster

## How It Works

The adapter bridges Harbor's scanning workflow with Kubescape's `kubevuln` component for image vulnerability analysis.

```
Harbor → harbor-scanner-kubescape → kubevuln (Kubescape)
                                         ↓
                                   Grype + Syft
                                         ↓
                               VulnerabilityManifest CRD
```

When Harbor triggers a scan:

1. Harbor sends a `POST /api/v1/scan` request to the adapter with the image details.
2. The adapter forwards the request to `kubevuln`, which scans the image using Grype and Syft.
3. Harbor polls `GET /api/v1/scan/{id}/report` until results are ready.
4. The vulnerability report is returned to Harbor and displayed in the registry UI.

## Installing the Adapter

### Step 1 — Install the Kubescape Operator

If the Kubescape operator is not already running in your cluster, install it via Helm:

```bash
helm repo add kubescape https://kubescape.github.io/helm-charts/
helm repo update
helm upgrade --install kubescape kubescape/kubescape-operator \
  --namespace kubescape \
  --create-namespace
```

Verify the `kubevuln` component is running:

```bash
kubectl get pods -n kubescape | grep kubevuln
```

### Step 2 — Deploy the Harbor Scanner Adapter

Deploy the adapter into the same namespace as Harbor:

```bash
helm install harbor-scanner-kubescape \
  oci://ghcr.io/onyx2406/harbor-scanner-kubescape/charts/harbor-scanner-kubescape \
  --namespace harbor \
  --set scanner.kubevulnURL=http://kubevuln.kubescape.svc.cluster.local:8080
```

Verify the adapter pod is running:

```bash
kubectl get pods -n harbor | grep harbor-scanner-kubescape
```

### Step 3 — Register the Scanner in Harbor

1. Log in to your Harbor instance as an administrator.
2. Go to **Administration → Interrogation Services → Scanners**.
3. Click **+ New Scanner**.
4. Fill in the following:
   - **Name**: `Kubescape`
   - **Endpoint**: `http://harbor-scanner-kubescape.harbor.svc.cluster.local:8080`
5. Click **Test Connection** to verify the adapter is reachable.
6. Click **Add** to save.

To set Kubescape as the default scanner for all projects, click the **⋮** menu next to the scanner and select **Set as Default**.

## Scanning Images

Once the adapter is registered, Harbor will use Kubescape to scan images automatically on push (if scan-on-push is enabled) or on demand.

### Enable Scan on Push

1. Go to your project in Harbor.
2. Click **Configuration**.
3. Enable **Automatically scan images on push**.
4. Click **Save**.

### Trigger a Manual Scan

1. Navigate to a repository in your project.
2. Click the **⋮** menu next to an image tag.
3. Select **Scan**.

Scan results appear in the **Vulnerabilities** column of the repository view.

## Configuration

The adapter is configured via environment variables. When deploying with Helm, pass values using `--set`:

| Variable | Default | Description |
|---|---|---|
| `SCANNER_API_ADDR` | `:8080` | Address the adapter HTTP server listens on |
| `KUBEVULN_URL` | `http://kubevuln:8080` | Base URL of the kubevuln service |
| `KUBEVULN_NAMESPACE` | `kubescape` | Kubernetes namespace for Kubescape components |
| `SCAN_REUSE_TTL` | `24h` | How long an existing scan result is reused before triggering a fresh scan. Set to `0` to always scan fresh. |
| `PERSISTENCE_BACKEND` | `memory` | Storage backend for scan jobs. Use `redis` for production multi-replica deployments. |

### Enabling TLS

By default the adapter serves plain HTTP and expects TLS termination at the cluster edge. To serve HTTPS directly:

```bash
kubectl create secret tls harbor-scanner-kubescape-tls \
  --cert=path/to/tls.crt \
  --key=path/to/tls.key \
  -n harbor

helm install harbor-scanner-kubescape \
  oci://ghcr.io/onyx2406/harbor-scanner-kubescape/charts/harbor-scanner-kubescape \
  --namespace harbor \
  --set tls.enabled=true \
  --set tls.secretName=harbor-scanner-kubescape-tls \
  --set service.port=8443
```

Update the scanner endpoint in Harbor to use `https://` and port `8443`.

### Production Deployment with Redis

For production deployments with multiple replicas, use the Redis persistence backend so scan state is shared across pods:

```bash
kubectl create secret generic harbor-scanner-redis \
  --from-literal=url=redis://:yourpassword@redis.harbor.svc.cluster.local:6379/0 \
  -n harbor

helm install harbor-scanner-kubescape \
  oci://ghcr.io/onyx2406/harbor-scanner-kubescape/charts/harbor-scanner-kubescape \
  --namespace harbor \
  --set persistence.backend=redis \
  --set persistence.redis.secretName=harbor-scanner-redis \
  --set replicaCount=2
```

## Troubleshooting

### Test Connection fails in Harbor

- Verify the adapter pod is running: `kubectl get pods -n harbor | grep harbor-scanner-kubescape`
- Check adapter logs: `kubectl logs -n harbor deployment/harbor-scanner-kubescape`
- Ensure the endpoint URL uses the correct service name and namespace.
- If using TLS, confirm the certificate is valid and the endpoint uses `https://`.

### Scans stay in Pending state

- Check that the `kubevuln` pod is running: `kubectl get pods -n kubescape | grep kubevuln`
- Verify the `KUBEVULN_URL` value matches the actual service address.
- Check kubevuln logs: `kubectl logs -n kubescape deployment/kubevuln`

### Scan results are stale

The adapter reuses existing `VulnerabilityManifest` CRDs for up to 24 hours by default. To force a fresh scan, set `SCAN_REUSE_TTL=0` in the Helm values, or trigger a manual scan from the Harbor UI.

### Pod restart causes scans to fail

With the default `memory` persistence backend, scan state is lost on pod restart. Ongoing scans return an error to Harbor. For production use, switch to the `redis` backend so state survives restarts.

## Further Reading

- [harbor-scanner-kubescape repository](https://github.com/Onyx2406/harbor-scanner-kubescape)
- [Harbor Pluggable Scanner API](https://github.com/goharbor/pluggable-scanner-spec)
- [Kubescape operator installation](https://kubescape.io/docs/operator/)
- [kubevuln component](https://github.com/kubescape/kubevuln)
- [Harbor documentation](https://goharbor.io/docs/)
