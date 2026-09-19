# Resource Streaming Implementation

## Overview

Kubescape previously loaded the entire cluster state into `AllResources` before evaluating anything. On clusters larger than ~2500 resources, this reached 2-4 GB of memory usage. The codebase contained an explicit admission of this workaround:

```go
// isLargeCluster returns true if the cluster size is larger than the largeClusterSize
// This code is a workaround for large clusters. The final solution will be to scan resources individually
```

This implementation fixes this in two ways:

- **Collection**: replaces the previous O(L × N) per-GVR-per-namespace traversals with a single cluster-wide traversal per GVR (O(L)), by walking each GVR once with `pager.EachListItem` and partitioning objects as they're yielded — cluster-scoped objects stay resident in memory, namespaced objects spill to an on-disk partition store in owner-only (`0700`) files and are loaded/purged one namespace at a time.
- **Evaluation**: namespace-scoped resources are streamed to the OPA processor in batches, so per-namespace evaluation never sees the whole cluster at once — only the resident (cluster-scoped) batch plus one namespace batch at a time. Whole-cluster controls default to the bounded `projected` policy, while `fallback` and `verify` intentionally evaluate against the full cluster.

**What this bounds:** with the scan-scoped partition store, the in-memory partition-store metadata and active pager buffer stay flat (~1-2 MB regardless of cluster size), bounding the *collection-phase memory peak* to the resident batch plus this small in-memory overhead. Required on-disk spill filesystem capacity grows with the raw JSON size of all namespaced resources (see Partition store notes below for disk-sizing guidance). Streaming also bounds the *evaluation input* and the *number of API-server calls*. Downstream stages access resources on demand via `ResourceCatalog`, and whole-cluster controls are bounded by execution policies (see below).

## Implementation Details

### 1. Streaming Interface (`core/pkg/resourcehandler/interface.go`)

Added to the `IResourceHandler` interface:

```go
StreamResourcesBatches(ctx context.Context, sessionObj *cautils.OPASessionObj, scanInfo *cautils.ScanInfo) (<-chan *cautils.ResourceBatch, <-chan error, error)
```

Returns channels for receiving resource batches and errors, so the caller can process resources incrementally.

### 2. K8sResourceHandler Streaming (`core/pkg/resourcehandler/k8sresources.go`)

Two-phase implementation:

- **Phase 1**: Collect the resident batch — cluster-scoped Kubernetes resources (Nodes, ClusterRoles, etc.), external resources (cloud/host scanner data, RBAC resources), and VAP resources (ValidatingAdmissionPolicy).
- **Phase 2**: Stream namespace-scoped resources in batches. Each batch contains only the resources belonging to one namespace, using `partitionstore.DiskStore` for spill (see Configuration below for storage/fallback behavior). Namespace batches are processed in sorted order for deterministic, reproducible results.

### 3. FileResourceHandler Streaming (`core/pkg/resourcehandler/filesloader.go`)

For file-based resources (typically smaller), all resources are loaded and returned as a single batch — file-based scans don't typically have memory issues, so the added complexity isn't warranted there.

### 4. OPA Processor Streaming (`core/pkg/opaprocessor/processorhandler.go`)

`ProcessWithStreaming` receives batches via channels, keeps the resident batch in memory throughout the scan, evaluates each namespace batch against it, and merges results. It reuses the existing `evaluationScope` and `matchedObjects` logic (see Related-Object Resolution below), so related-object resolution keeps working across batches since cluster-scoped resources remain resident.

### 5. Scan Command Integration (`core/core/scan.go`, `cmd/scan/scan.go`)

Added CLI flag `--enable-streaming`, auto-enabled for clusters over the `LARGE_CLUSTER_SIZE` threshold (see Configuration).

### 6. ScanInfo Update (`core/cautils/scaninfo.go`)

Added `EnableStreaming` field to `ScanInfo` to control streaming behavior.

## Whole-Cluster Control Execution Policies

Controls marked `requiresWholeClusterInput` (e.g. `C-0261`, `C-0266`, `C-0267`, `C-0272`) perform cross-namespace joins — service accounts bound by cross-namespace RoleBindings, Gateway API ingress, etc. — and evaluating them per-namespace would lose those relationships, so they're deferred until after per-namespace evaluation completes.

Execution is governed by explicit `--whole-cluster-policy`, then `KUBESCAPE_WHOLE_CLUSTER_POLICY`, then `KUBESCAPE_WHOLE_CLUSTER_PARITY_CHECK=true` (selecting `verify`), defaulting to `projected`:

1. **`projected` (default)** — evaluates whole-cluster controls against an incrementally accumulated working set containing *only* resources matching their rule declarations (Pods, ServiceAccounts, RoleBindings, Gateways, etc.). Unrelated resources (ConfigMaps, Secrets, CronJobs, custom resources — typically 90-98% of a large cluster) are omitted from the index. Bounds evaluation memory and indexing CPU in both streaming and non-streaming modes. Parity against full-cluster evaluation depends on complete rule match declarations and can be checked using `verify` mode.
2. **`fallback`** — materializes the entire cluster into memory and evaluates against `snapshotAllResources()`, logging an informational message about the full-memory materialization.
3. **`skip`** — bypasses whole-cluster controls entirely, for extreme memory-constrained environments (e.g. edge nodes with 128MB RAM). Skipped controls are recorded in `ScanCoverage.NotEvaluatedControls` with a traceable reason, and the standard `CoverageScore` penalty applies, so posture audits stay accurate and CI can't silently evade coverage.
4. **`verify`** — debug cross-check mode: runs whole-cluster controls against both `projected` and `fallback` scopes and reports any verdict divergence (can be enabled via `--whole-cluster-policy=verify`, `KUBESCAPE_WHOLE_CLUSTER_POLICY=verify`, or `KUBESCAPE_WHOLE_CLUSTER_PARITY_CHECK=true` when no explicit policy is specified).

## Related-Object Resolution

`matchedObjects` already handled cross-scope resolution correctly and needed no changes:

```go
func (scope evaluationScope) matchedObjects(rule *reporthandling.PolicyRule) []workloadinterface.IMetadata {
	var objects []workloadinterface.IMetadata
	if scope.batch != nil {
		objects = getKubernetesObjects(scope.batch.K8SResources, scope.batch.AllResources, rule.Match)
		if len(objects) == 0 {
			return nil
		}
	}
	objects = append(objects, getKubernetesObjects(scope.resident.K8SResources, scope.resident.AllResources, rule.Match)...)
	objects = append(objects, getKubernetesObjectsFromExternalResources(scope.resident.ExternalResources, scope.resident.AllResources, rule.DynamicMatch)...)
	return objects
}
```

When evaluating a namespace batch (`scope.batch != nil`), `scope.resident` resources are appended to provide related cluster-scoped context whenever the namespace batch contributes matching objects (if the batch contributes no matching objects, `matchedObjects` returns early). Purely cluster-scoped evaluation occurs separately during the resident scope (`scope.batch == nil`).

## Testing

`core/pkg/opaprocessor/processorhandler_streaming_test.go`:

- **TestProcessWithStreaming_Parity** — confirms resource partitioning is correct for both small and large clusters, and that small clusters (<2500 resources) still use a single resident batch (backward compatible) while large clusters (>2500) split into multiple namespace batches, with cluster- and namespace-scoped resources partitioned correctly.
- **TestResourceBatch_MemoryUsage** — confirms namespace batches are partitioned correctly.

Collection-phase in-memory claims (flat ~1-2 MB partition-store metadata and pager buffer baseline across cluster sizes; on-disk spill capacity scales with namespaced resource raw JSON) are verified across 5k, 20k, and 50k synthetic clusters with 50-200 resident nodes in `BenchmarkStreamingCollectorMemory`.

## Performance Impact

**API-server calls:**
- Small clusters (<2500 resources): by default in automatic mode, no change (single-batch collection mode); however, if streaming is explicitly enabled via `--enable-streaming=true`, small clusters can still utilize the streaming O(L) cluster-wide GVR traversal pattern.
- Large clusters (>2500 resources): logical GVR traversals drop from O(L × N) (one per GVR per namespace) to O(L) (one cluster-wide traversal per GVR). For a cluster with 2,500 namespaces and 100 GVRs, this reduces ~250,000 logical traversals down to ~100 logical traversals. Note that because `pager.EachListItem` paginates (using chunked LIST requests based on page size and resource count, just as the per-namespace path could also paginate), the physical number of HTTP LIST calls depends on total object count and page size, but eliminates the O(N) namespace multiplication factor entirely.

**CPU:** minimal added overhead from the streaming goroutine, channel operations, and batch management — evaluation may be slightly slower than the non-streaming path due to batching overhead, but this is outweighed by the API-server savings on large clusters.

## Configuration

| Flag / Env Var | Default | Effect |
|---|---|---|
| `--enable-streaming` | auto — enabled above `LARGE_CLUSTER_SIZE` | Manually force streaming on/off (`--enable-streaming=false` to disable) |
| `LARGE_CLUSTER_SIZE` | `2500` | Resource-count threshold for auto-enabling streaming |
| `--whole-cluster-policy` | `projected` | Execution policy for whole-cluster controls (`projected` / `fallback` / `skip` / `verify`) |
| `KUBESCAPE_WHOLE_CLUSTER_POLICY` | `projected` | Env-var equivalent of `--whole-cluster-policy` |
| `KUBESCAPE_WHOLE_CLUSTER_PARITY_CHECK` | `false` | Set `true` to run the `verify` cross-check mode when neither an explicit `--whole-cluster-policy` nor a non-empty `KUBESCAPE_WHOLE_CLUSTER_POLICY` is set (not a required companion setting if policy is explicitly set) |
| `KUBESCAPE_SPILL_DIR` | `$TMPDIR` (falls back to `os.TempDir()`) | Base directory for the on-disk partition store |
| `KUBESCAPE_PARTITION_STORE` | `disk` | Set `memory` to disable disk spilling entirely |

**Partition store notes:**
- Peak disk usage is proportional to the raw JSON size of all namespaced resources in the cluster; partitions are purged (`store.PurgeNamespace`) immediately after a namespace batch is loaded and streamed, so disk usage is reclaimed incrementally as the scan progresses.
- In constrained environments (e.g. operator pods with `readOnlyRootFilesystem: true` and no writable `/tmp`), if the spill directory can't be created, the collector logs a warning and falls back automatically to `partitionstore.NewMemoryStore()`. **Warning:** `NewMemoryStore()` retains all committed namespaced resources in Go heap memory until each namespace batch is loaded and purged, making collection memory usage unbounded and proportional to the full cluster's namespaced resources; on large clusters, this fallback risks out-of-memory (OOM) termination. Ensure a writable spill directory (`KUBESCAPE_SPILL_DIR` or `/tmp`) is mounted in memory-constrained environments.

## Future Enhancements

1. Accurate cluster-size estimation (currently a placeholder; should use proper Kubernetes API discovery).
2. Adaptive batch sizing based on available memory.
3. Parallel batch processing across namespaces (with proper synchronization).
4. Metrics/monitoring for memory usage and streaming performance.

## Compatibility

- Backward compatible streaming selection: clusters below the `LARGE_CLUSTER_SIZE` threshold (or when `--enable-streaming=false`) keep using the single-batch collection approach.
- Opt-in / opt-out via `--enable-streaming`.
- Threshold adjustable via `LARGE_CLUSTER_SIZE`.
- Note: Whole-cluster controls default to `projected` policy regardless of cluster size or streaming mode to bound indexing CPU and memory. Users requiring legacy full-memory materialization for whole-cluster controls can explicitly set `--whole-cluster-policy=fallback`.

## Conclusion

Collection uses a single cluster-wide traversal per GVR instead of one per GVR per namespace, and namespace evaluation is streamed so the OPA processor never sees the whole cluster at once during per-namespace evaluation. With the partition store integrated, the collection-phase in-memory peak is bounded to the resident batch plus flat partition-store metadata and pager buffers (~1-2 MB), while namespaced objects spill to disk. Downstream stages access resources on demand via `ResourceCatalog`, and whole-cluster controls default to a bounded projected working set (with explicit full-cluster fallback and parity verify modes when needed) — preserving cross-namespace join fidelity without unbounded memory growth.
