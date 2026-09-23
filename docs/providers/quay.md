# Red Hat Quay (`quay.io`) Provider Guide

Kubescape supports retrieving vulnerability reports and security scan statuses directly from **Red Hat Quay** (both the public SaaS registry at [`quay.io`](https://quay.io) and private, self-hosted Red Hat Quay enterprise deployments).

This integration leverages Quay's Security API powered by the **Clair** static analysis engine, allowing Kubescape to evaluate image security without needing to pull and rescan image layers locally when Quay has already indexed them.

---

## Authentication Methods

Quay supports two primary methods for API authentication:

### 1. Robot Accounts (Recommended for CI/CD)
Robot accounts are automated service credentials scoped to specific repositories or organizations in Quay.
* **Username Format**: `<organization>+<robot_name>` (e.g. `myorg+ci_scanner`)
* **Password**: The generated robot token string

When configuring Kubescape:
```bash
export KUBESCAPE_REGISTRY_USERNAME="myorg+ci_scanner"
export KUBESCAPE_REGISTRY_PASSWORD="<robot-token>"
```

### 2. OAuth2 / Application Bearer Tokens
Personal access tokens or OAuth2 application tokens created under Quay Account Settings.
* **Header**: `Authorization: Bearer <token>`

When configuring Kubescape:
```bash
export KUBESCAPE_REGISTRY_TOKEN="<oauth2-bearer-token>"
```

### 3. Public Images (Unauthenticated)
For publicly accessible images on `quay.io` (such as `quay.io/coreos/etcd`), no credentials are required. Kubescape will query Quay's public discovery and manifest endpoints anonymously.

---

## Quay Security API & Clair Integration

Kubescape communicates with Quay's canonical manifest security endpoint:
```http
GET /api/v1/repository/{organization}/{repository}/manifest/{manifestref}/security?vulnerabilities=true
```

Where `{manifestref}` is a content-addressable manifest digest (e.g. `sha256:d12345...`). For tag-only image identifiers (e.g. `:v3.5.0` or `:latest`), Kubescape first resolves the tag through the registry manifest endpoint (`GET /v2/{org}/{repo}/manifests/{tag}`), using the registry token challenge flow so that robot accounts work. If that lookup fails, Kubescape falls back to Quay's tag API (`GET /api/v1/repository/{org}/{repo}/tag/?specificTag={tag}&onlyActiveTags=true`). If a tag points to a manifest list or OCI index, Kubescape selects the platform child manifest digest (preferring `linux/amd64`, then any `linux`) before it queries the security endpoint. If a supplied digest is a manifest list and the security endpoint returns `unsupported`, Kubescape resolves the child digest and repeats the query.

Nested repositories (e.g. `org/team/app`) are supported for self-hosted Quay 3.6+ deployments with `FEATURE_EXTENDED_REPOSITORY_NAMES` enabled.

### Severity Mapping
Clair reports severities that Kubescape normalizes to its standard security posture levels:

| Quay / Clair Severity | Kubescape Normalized Severity |
| :--- | :--- |
| `Defcon1` | `Critical` |
| `Critical` | `Critical` |
| `High` | `High` |
| `Medium` | `Medium` |
| `Low` | `Low` |
| `Negligible`, `Minimal`, `None` | `Negligible` |
| `Unknown` | `Unknown` |

---

## Self-Hosted Red Hat Quay Deployments

For on-premises enterprise Quay installations (e.g., deployed on OpenShift or private Kubernetes clusters), specify the fully qualified domain name:

```bash
# HTTPS private registry
https://quay.internal.corp:8443

# Insecure HTTP (development or test clusters)
http://quay-registry.local:8080
```

Kubescape normalizes URL schemes, verifies API compatibility against `/api/v1/discovery`, supports nested repository paths, and honors standard proxy and TLS configuration.

---

## Programmatic Usage & Functional Options

The Quay adaptor implements `IContainerImageVulnerabilityAdaptor` and supports functional options for fine-grained configuration:

```go
package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/kubescape/kubescape/v4/pkg/imagescan"
)

func main() {
	ctx := context.Background()

	// Optional custom transport for enterprise TLS or proxies
	customTransport := http.DefaultTransport

	// Configure custom timeouts, retries, and HTTP client
	adaptor := imagescan.NewQuayAdaptor(
		imagescan.WithTimeout(30 * time.Second),
		imagescan.WithMaxRetries(5),
		imagescan.WithRetryBackoff(500 * time.Millisecond),
		imagescan.WithMaxResponseSize(32 * 1024 * 1024), // 32MB limit
		imagescan.WithHTTPClient(&http.Client{
			Transport: customTransport, // Custom TLS/proxy settings
		}),
	)

	// Authenticate and verify reachability first
	if err := adaptor.Login(ctx, "https://quay.internal.corp:8443", imagescan.RegistryCredentials{
		Token: os.Getenv("KUBESCAPE_REGISTRY_TOKEN"),
	}); err != nil {
		fmt.Fprintf(os.Stderr, "login failed: %v\n", err)
		return
	}

	// Check if Clair security scanner is enabled on the target registry
	enabled, err := adaptor.CheckScannerCapability(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "capability check failed: %v\n", err)
		return
	}
	fmt.Printf("Clair security scanner enabled: %t\n", enabled)
}
```

### Supported Configuration Options

| Option | Default | Description |
| :--- | :--- | :--- |
| `WithTimeout(d)` | `15s` | Timeout for individual HTTP requests to Quay |
| `WithMaxRetries(n)` | `3` | Maximum retry attempts for transient network failures and 429 rate limits |
| `WithRetryBackoff(d)` | `500ms` | Base exponential backoff duration between retry attempts |
| `WithMaxResponseSize(bytes)` | `64MB` | Maximum permitted response payload size to prevent resource exhaustion |
| `WithHTTPClient(client)` | Standard client | Custom `*http.Client` for enterprise proxies or custom TLS CAs |
| `WithInsecureHTTPCredentials()` | `false` | Explicit opt-in to allow transmitting credentials over plain unencrypted HTTP (e.g. for local test environments) |

---

## Rate Limiting & Resilience

* **HTTP 429 Backoff**: The adaptor inspects Quay's `Retry-After` header when rate limits are encountered and sleeps for the requested interval before retrying.
* **Oversized Response Protection**: Registry responses exceeding 64MB (or custom configured threshold) are safely rejected via streaming body limiters to guard against memory exhaustion.
* **CVE Deduplication**: Vulnerability reports spanning multiple image layers or package dependencies are automatically deduplicated by CVE identifier, preserving the highest reported severity across occurrences.
