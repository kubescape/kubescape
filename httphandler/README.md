# Kubescape HTTP Handler

The HTTP Handler provides a REST API for running Kubescape scans programmatically. This enables integration with CI/CD pipelines, custom dashboards, and automation workflows.

## Table of Contents

- [Overview](#overview)
- [API Reference](#api-reference)
  - [Trigger Scan](#trigger-scan)
  - [Get Results](#get-results)
  - [Check Status](#check-status)
  - [Delete Results](#delete-results)
- [Request/Response Objects](#requestresponse-objects)
- [API Examples](#api-examples)
- [Environment Variables](#environment-variables)
- [Deployment Examples](#deployment-examples)
- [Debugging](#debugging)

---

## Overview

When running Kubescape as a service, it starts a web server on port `8080` that exposes REST APIs for:

- Triggering security scans (async or sync)
- Retrieving scan results
- Checking scan status
- Managing cached results

---

## API Reference

### Trigger Scan

**Endpoint:** `POST /v1/scan`

Triggers a Kubescape scan. By default, scans run asynchronously and return a scan ID immediately.

**Query Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `wait` | bool | `false` | Wait for scan to complete (synchronous mode) |
| `keep` | bool | `false` | Keep results in cache after returning |

**Request Body:** See [Trigger Scan Object](#trigger-scan-object)

**Response (async):**

```json
{
  "id": "scan-12345",
  "type": "busy",
  "response": "scanning in progress"
}
```

**Response (sync with `wait=true`):** Same as [Get Results](#get-results) response.

---

### Get Results

**Endpoint:** `GET /v1/results`

Retrieve scan results.

**Query Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `id` | string | - | Scan ID. If empty, returns latest results |
| `keep` | bool | `false` | Keep results in cache after returning |

**Response (success):**

```json
{
  "id": "scan-12345",
  "type": "v1results",
  "response": { /* scan results object */ }
}
```

**Response (error):**

```json
{
  "id": "scan-12345",
  "type": "error",
  "response": "error message"
}
```

**Response (in progress):**

```json
{
  "id": "scan-12345",
  "type": "busy",
  "response": "scanning in progress"
}
```

---

### Check Status

**Endpoint:** `GET /v1/status`

Check if a scan is still in progress. Useful for polling without retrieving full results.

**Query Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `id` | string | - | Scan ID. If empty, checks if any scan is in progress |

**Response (in progress):**

```json
{
  "id": "scan-12345",
  "type": "busy",
  "response": "scanning in progress"
}
```

**Response (complete):**

```json
{
  "id": "scan-12345",
  "type": "notBusy",
  "response": "scanning completed"
}
```

---

### Delete Results

**Endpoint:** `DELETE /v1/results`

Delete cached scan results.

**Query Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `id` | string | - | Scan ID to delete. If empty, deletes latest |
| `all` | bool | `false` | Delete all cached results |

---

## Request/Response Objects

### Trigger Scan Object

```json
{
  "format": "json",
  "excludedNamespaces": ["kube-system", "kube-public"],
  "includeNamespaces": ["production", "staging"],
  "useCachedArtifacts": false,
  "keepLocal": true,
  "account": "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX",
  "accessKey": "your-access-key",
  "targetType": "framework",
  "targetNames": ["nsa", "mitre"]
}
```

| Field | Type | Description |
|-------|------|-------------|
| `format` | string | Output format (default: `json`) |
| `excludedNamespaces` | []string | Namespaces to exclude from scan |
| `includeNamespaces` | []string | Namespaces to include in scan |
| `useCachedArtifacts` | bool | Use cached artifacts (offline mode) |
| `keepLocal` | bool | Don't submit results to backend |
| `account` | string | Kubescape SaaS account ID |
| `accessKey` | string | Kubescape SaaS access key |
| `targetType` | string | `"framework"` or `"control"` |
| `targetNames` | []string | Frameworks/controls to scan |

### Response Object

```json
{
  "id": "scan-12345",
  "type": "v1results",
  "response": { /* payload */ }
}
```

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | Scan identifier |
| `type` | string | Response type (see below) |
| `response` | any | Response payload |

**Response Types:**

| Type | Description |
|------|-------------|
| `v1results` | Scan results object |
| `busy` | Scan in progress |
| `notBusy` | No scan in progress |
| `ready` | Scan complete, results ready |
| `error` | Error occurred |

---

## API Examples

### Basic Scan (Async)

```bash
# 1. Trigger scan
curl -X POST http://127.0.0.1:8080/v1/scan \
  -H "Content-Type: application/json" \
  -d '{"targetType": "framework", "targetNames": ["nsa"]}'

# 2. Check status
curl http://127.0.0.1:8080/v1/status

# 3. Get results
curl http://127.0.0.1:8080/v1/results -o results.json
```

### Synchronous Scan

```bash
curl -X POST "http://127.0.0.1:8080/v1/scan?wait=true" \
  -H "Content-Type: application/json" \
  -d '{"targetType": "framework", "targetNames": ["nsa"]}' \
  -o results.json
```

### Scan Specific Namespaces

```bash
curl -X POST http://127.0.0.1:8080/v1/scan \
  -H "Content-Type: application/json" \
  -d '{
    "includeNamespaces": ["production"],
    "targetType": "framework",
    "targetNames": ["nsa", "mitre"]
  }'
```

### Scan with Account Integration

```bash
curl -X POST http://127.0.0.1:8080/v1/scan \
  -H "Content-Type: application/json" \
  -d '{
    "account": "YOUR-ACCOUNT-ID",
    "accessKey": "YOUR-ACCESS-KEY",
    "targetType": "framework",
    "targetNames": ["nsa"]
  }'
```

### Delete All Cached Results

```bash
curl -X DELETE "http://127.0.0.1:8080/v1/results?all=true"
```

---

## Environment Variables

Configure the HTTP handler using environment variables:

| Variable | Description | Example |
|----------|-------------|---------|
| `KS_ACCOUNT` | Default account ID | `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx` |
| `KS_EXCLUDE_NAMESPACES` | Default namespaces to exclude | `kube-system,kube-public` |
| `KS_INCLUDE_NAMESPACES` | Default namespaces to include | `production,staging` |
| `KS_FORMAT` | Default output format | `json` |
| `KS_LOGGER_NAME` | Logger name | `kubescape` |
| `KS_LOGGER_LEVEL` | Log level | `info`, `debug`, `warning`, `error` |
| `KS_DOWNLOAD_ARTIFACTS` | Download artifacts on each scan | `true`, `false` |

---

## Deployment Examples

### Microservice Deployment

Deploy Kubescape as a microservice in your cluster for API-driven scanning.

📖 **[Microservice Deployment Guide →](examples/microservice/README.md)**

### Prometheus Integration

Expose Kubescape metrics for Prometheus scraping.

📖 **[Prometheus Integration Guide →](examples/prometheus/README.md)**

---

## Debugging

### Enable Debug Logging

Set the log level to debug for more verbose output:

```bash
export KS_LOGGER_LEVEL=debug
```

### Performance Profiling

The HTTP handler exposes pprof endpoints for performance analysis:

```bash
# Heap profile
go tool pprof http://localhost:6060/debug/pprof/heap

# CPU profile
go tool pprof http://localhost:6060/debug/pprof/profile?seconds=30

# Goroutine profile
go tool pprof http://localhost:6060/debug/pprof/goroutine
```

For more information on pprof, see the [pprof documentation](https://pkg.go.dev/net/http/pprof).

---

## Related Documentation

- [CLI Reference](../docs/cli-reference.md)
- [Architecture](../docs/architecture.md)
- [Getting Started Guide](../docs/getting-started.md)
- [Troubleshooting](../docs/troubleshooting.md)