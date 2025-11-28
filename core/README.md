# Kubescape Core Package

The `core` package provides the main Kubescape scanning engine as a Go library, allowing you to integrate Kubescape security scanning directly into your applications.

## Table of Contents

- [Installation](#installation)
- [Quick Start](#quick-start)
- [API Reference](#api-reference)
- [Examples](#examples)
- [Configuration Options](#configuration-options)

---

## Installation

```bash
go get github.com/kubescape/kubescape/v3/core
```

---

## Quick Start

```go
package main

import (
    "context"
    "fmt"
    "log"

    "github.com/kubescape/kubescape/v3/core"
    "github.com/kubescape/kubescape/v3/core/cautils"
)

func main() {
    ctx := context.Background()

    // Initialize Kubescape
    ks := core.NewKubescape(ctx)

    // Configure scan
    scanInfo := &cautils.ScanInfo{
        // Scan the current cluster
        ScanAll: true,
    }

    // Run scan
    results, err := ks.Scan(scanInfo)
    if err != nil {
        log.Fatalf("Scan failed: %v", err)
    }

    // Convert results to JSON
    jsonRes, err := results.ToJson()
    if err != nil {
        log.Fatalf("Failed to convert results: %v", err)
    }

    fmt.Println(string(jsonRes))
}
```

---

## API Reference

### Creating a Kubescape Instance

```go
// Create with context
ks := core.NewKubescape(ctx)
```

### Scanning

```go
// Scan with configuration
results, err := ks.Scan(scanInfo)
```

### Listing Frameworks and Controls

```go
// List available policies
err := ks.List(listPolicies)
```

### Downloading Artifacts

```go
// Download for offline use
err := ks.Download(downloadInfo)
```

### Image Scanning

```go
// Scan container image
exceedsSeverity, err := ks.ScanImage(imgScanInfo, scanInfo)
```

### Fixing Misconfigurations

```go
// Apply fixes to manifests
err := ks.Fix(fixInfo)
```

---

## Examples

### Scan a Specific Framework

```go
scanInfo := &cautils.ScanInfo{}
scanInfo.SetPolicyIdentifiers([]string{"nsa"}, "framework")

results, err := ks.Scan(scanInfo)
```

### Scan Specific Namespaces

```go
scanInfo := &cautils.ScanInfo{
    IncludeNamespaces: "production,staging",
}

results, err := ks.Scan(scanInfo)
```

### Scan Local YAML Files

```go
scanInfo := &cautils.ScanInfo{
    InputPatterns: []string{"/path/to/manifests"},
}
scanInfo.SetScanType(cautils.ScanTypeRepo)

results, err := ks.Scan(scanInfo)
```

### Export Results to Different Formats

```go
results, _ := ks.Scan(scanInfo)

// JSON
jsonData, _ := results.ToJson()

// Get summary
summary := results.GetData().Report.SummaryDetails
fmt.Printf("Compliance Score: %.2f%%\n", summary.ComplianceScore)
```

### Scan with Compliance Threshold

```go
scanInfo := &cautils.ScanInfo{
    ComplianceThreshold: 80.0, // Fail if below 80%
}

results, err := ks.Scan(scanInfo)
if err != nil {
    // Handle scan failure
}

// Check if threshold was exceeded
if results.GetData().Report.SummaryDetails.ComplianceScore < scanInfo.ComplianceThreshold {
    log.Fatal("Compliance score below threshold")
}
```

---

## Configuration Options

### ScanInfo Fields

| Field | Type | Description |
|-------|------|-------------|
| `AccountID` | string | Kubescape SaaS account ID |
| `AccessKey` | string | Kubescape SaaS access key |
| `InputPatterns` | []string | Paths to scan (files, directories, URLs) |
| `ExcludedNamespaces` | string | Comma-separated namespaces to exclude |
| `IncludeNamespaces` | string | Comma-separated namespaces to include |
| `Format` | string | Output format (json, junit, sarif, etc.) |
| `Output` | string | Output file path |
| `VerboseMode` | bool | Show all resources in output |
| `FailThreshold` | float32 | Fail threshold percentage |
| `ComplianceThreshold` | float32 | Compliance threshold percentage |
| `UseExceptions` | string | Path to exceptions file |
| `UseArtifactsFrom` | string | Path to offline artifacts |
| `Submit` | bool | Submit results to SaaS |
| `Local` | bool | Keep results local (don't submit) |

---

## Error Handling

```go
results, err := ks.Scan(scanInfo)
if err != nil {
    switch {
    case errors.Is(err, context.DeadlineExceeded):
        log.Fatal("Scan timed out")
    case errors.Is(err, context.Canceled):
        log.Fatal("Scan was canceled")
    default:
        log.Fatalf("Scan error: %v", err)
    }
}
```

---

## Thread Safety

The Kubescape instance is safe for concurrent use. You can run multiple scans in parallel:

```go
var wg sync.WaitGroup

for _, ns := range namespaces {
    wg.Add(1)
    go func(namespace string) {
        defer wg.Done()
        
        scanInfo := &cautils.ScanInfo{
            IncludeNamespaces: namespace,
        }
        results, _ := ks.Scan(scanInfo)
        // Process results...
    }(ns)
}

wg.Wait()
```

---

## Related Documentation

- [CLI Reference](../docs/cli-reference.md)
- [Getting Started Guide](../docs/getting-started.md)
- [Architecture](../docs/architecture.md)