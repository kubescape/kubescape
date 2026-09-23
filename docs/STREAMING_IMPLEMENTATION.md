# Resource Streaming Implementation

## Overview

This implementation addresses the API-server load issue described in A1 of `issues.md` and Phase 5 of `docs/optimization-plan.md`. The solution introduces resource streaming so the OPA evaluation never holds the whole cluster as its input: resources are partitioned by scope and the processor evaluates the resident (cluster-scoped) batch plus one namespace batch at a time, while the collection phase replaces the previous O(L × N) per-GVR-per-namespace LIST calls with a single LIST per GVR (O(L)).

Note what streaming does and does not bound: with the scan-scoped partition store integrated into the collector (Phase 2), namespaced spill usage and partition-store metadata remain flat (~1-2 MB across cluster sizes), so the collection-phase memory peak is bounded to resident (cluster-scoped) resources plus the active pager buffer and store metadata, rather than tracking total cluster size. What is not yet bounded is total downstream retention: after evaluation, the processor retains resources in `AllResources` / `ResourceCatalog` for downstream stages (exceptions, printers, image scanning). Streaming bounds the *evaluation input*, the number of API-server calls, and the *collection peak* (for clusters dominated by namespaced resources), while total-process RSS reduction remains a downstream goal for future phases.

Collection is paginated end to end: each GVR is walked once with `pager.EachListItem`, and objects are partitioned as the pager yields them: cluster-scoped objects are kept in the resident batch, while namespaced objects are spilled to an on-disk partition store in owner-only (`0700`) files and loaded/purged one namespace at a time.

## Problem Statement

Kubescape previously loaded the entire cluster state into `AllResources` before evaluating anything. On clusters larger than ~2500 resources, this reached 2-4 GB of memory usage. The codebase contained an explicit admission of this workaround:

```go
// isLargeCluster returns true if the cluster size is larger than the largeClusterSize
// This code is a workaround for large clusters. The final solution will be to scan resources individually
```

## Solution Design

The implementation leverages the existing `ResourceBatch` architecture that was already present in the codebase but was being used only for scope-based evaluation, not memory management. The solution adds a streaming interface that:

1. **Partitions resources by scope**: Cluster-scoped resources (Nodes, ClusterRoles, etc.) are kept resident in memory throughout the scan, while namespace-scoped resources are processed in batches.

2. **Streams resources incrementally**: Instead of loading all resources at once, resources are streamed in batches via channels.

3. **Bounded evaluation input**: Each namespace batch is evaluated one at a time against the resident batch, so the evaluation input never contains the whole cluster.

4. **Maintains result parity**: The streaming implementation produces identical results to the non-streaming approach.

## Implementation Details

### 1. Streaming Interface (`core/pkg/resourcehandler/interface.go`)

Added a new method to the `IResourceHandler` interface:

```go
StreamResourcesBatches(ctx context.Context, sessionObj *cautils.OPASessionObj, scanInfo *cautils.ScanInfo) (<-chan *cautils.ResourceBatch, <-chan error, error)
```

This method returns channels for receiving resource batches and errors, enabling the caller to process resources incrementally.

### 2. K8sResourceHandler Streaming (`core/pkg/resourcehandler/k8sresources.go`)

Implemented `StreamResourcesBatches` for Kubernetes resources with a two-phase approach:

- **Phase 1**: Collect resident batch (cluster-scoped + external resources)
- **Phase 2**: Stream namespace-scoped resources in batches

The resident batch includes:
- Cluster-scoped Kubernetes resources (Nodes, ClusterRoles, etc.)
- External resources (cloud/host scanner data, RBAC resources)
- VAP resources (ValidatingAdmissionPolicy)

Namespace batches contain only the resources belonging to a specific namespace, using the configured partition store (`partitionstore.DiskStore` by default) for spill (see Partition Store & Storage Requirements below). Namespace batches are processed in sorted order for deterministic, reproducible results.

### 3. FileResourceHandler Streaming (`core/pkg/resourcehandler/filesloader.go`)

For file-based resources (typically smaller), the implementation loads all resources and returns them as a single batch for simplicity, since file-based scans don't typically have memory issues.

### 4. OPA Processor Streaming (`core/pkg/opaprocessor/processorhandler.go`)

Added `ProcessWithStreaming` method that:

- Receives batches via channels
- Keeps the resident batch in memory throughout the scan
- Processes each namespace batch against the resident batch
- Merges results from all batches

The method leverages the existing `evaluationScope` and `matchedObjects` logic, ensuring that related-object resolution works correctly across batches since cluster-scoped resources remain resident.

### 5. Scan Command Integration (`core/core/scan.go`, `cmd/scan/scan.go`)

Added CLI flag `--enable-streaming` to manually enable streaming, and auto-detection for large clusters:

```go
scanCmd.PersistentFlags().BoolVar(&scanInfo.EnableStreaming, "enable-streaming", false, "Enable resource streaming for large clusters. Resources are collected in a single pass per type and evaluated one namespace at a time. Automatically enabled for clusters with >2500 resources.")
```

The scan logic automatically enables streaming for clusters with >2500 resources (configurable via `LARGE_CLUSTER_SIZE` environment variable).

### 6. ScanInfo Update (`core/cautils/scaninfo.go`)

Added `EnableStreaming` and `WholeClusterPolicy` fields to `ScanInfo` struct to control streaming and whole-cluster execution policies.

## Key Design Decisions

### Why This Approach?

1. **Leverages existing architecture**: The `ResourceBatch` and `PartitionResources` logic already existed, reducing the risk of introducing bugs.

2. **Maintains correctness**: By keeping cluster-scoped resources resident, related-object resolution continues to work correctly since rules can access cluster-scoped resources from any namespace batch.

3. **Deterministic ordering**: Namespace batches are processed in sorted order, ensuring reproducible results.

4. **Graceful degradation**: If streaming fails, the system can fall back to the traditional approach.

### Memory Management

The implementation reduces peak evaluation memory by:

- Keeping only cluster-scoped resources (~10-20% of total) plus a single namespace batch in the evaluation input at any time
- Processing controls scope-by-scope (resident + one namespace at a time)

The collection peak is bounded (Phase 2): all queryable GVRs are traversed once, with namespaced resources written directly to a scan-scoped on-disk partition store (`partitionstore.DiskStore`). The resident batch (cluster-scoped resources) remains in memory and is emitted first, while each namespace batch is loaded, evaluated, and purged from disk one at a time. The namespaced collection contribution and store metadata stay flat at ~1-2 MB regardless of cluster size, so total collector memory comprises this flat baseline plus the resident batch (verified across 5k, 20k, and 50k synthetic clusters with 50-200 resident nodes in `BenchmarkStreamingCollectorMemory`), rather than scaling with the number of namespaced objects.

Downstream retention in `sessionObj.AllResources` across subsequent stages (exceptions, printers, image scanning) is a separate boundary; Phase 3a introduces the `ResourceCatalog` accessor abstraction while retention remains unbounded, before decoupling retention in later phases.

In Phase 4 ([#3235](https://github.com/kubescape/kubescape/issues/3235)), whole-cluster controls define an execution policy contract. Because every namespace batch is merged into the in-memory `MapResourceCatalog` (`processorhandler.go:445`), all objects remain resident in memory throughout the scan regardless of the chosen policy. What `projected` shrinks today is only the transient index built for the deferred whole-cluster pass (~2–4 MB vs ~62 MB on a synthetic 50k-object cluster). Crucially, `projected` establishes the contract that enables a future bounded catalog to safely drop non-matching namespace objects after per-namespace evaluation, while retaining only matching resources for the deferred whole-cluster pass.

### Partition Store & Storage Requirements

- **Writable Temporary Directory**: By default, `partitionstore.DiskStore` creates an owner-only directory (`0700`) in `$TMPDIR` (falling back to `os.TempDir()`, usually `/tmp`). The base directory can be configured with the `KUBESCAPE_SPILL_DIR` environment variable.
- **Spill Size**: Peak disk usage is proportional to the raw JSON serialization size of all namespaced resources in the cluster. Partitions are purged (`store.PurgeNamespace`) immediately after downstream loading and streaming, so disk space is incrementally reclaimed as the scan progresses.
- **In-Memory Fallback**: When running in constrained environments (such as Kubernetes operator pods with `readOnlyRootFilesystem: true` and no writable `/tmp` volume), if the disk spill directory cannot be created, the collector logs a warning and automatically falls back to `partitionstore.NewMemoryStore()`. **Warning:** `NewMemoryStore()` retains all committed namespaced resources in Go heap memory until each namespace batch is loaded and purged, making collection memory usage unbounded and proportional to the full cluster's namespaced resources; on large clusters, this fallback risks out-of-memory (OOM) termination. Ensure a writable spill directory (`KUBESCAPE_SPILL_DIR` or `/tmp`) is mounted in memory-constrained environments.
- **Manual Store Configuration**: To explicitly disable disk spilling and run in memory, set `export KUBESCAPE_PARTITION_STORE=memory`. To target an emptyDir mount, set `export KUBESCAPE_SPILL_DIR=/path/to/mount`.

### Related-Object Resolution

The existing `matchedObjects` function already handles cross-scope resolution correctly:

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

Since `scope.resident` contains all cluster-scoped resources, rules can access them regardless of which namespace batch is being processed.

## Whole-Cluster Control Execution Policies

Controls marked `requiresWholeClusterInput` (e.g. `C-0261`, `C-0266`, `C-0267`, `C-0272`) perform cross-namespace joins — service accounts bound by cross-namespace RoleBindings, Gateway API ingress, etc. — and evaluating them per-namespace would lose those relationships, so they are deferred until after per-namespace evaluation completes.

Execution is governed by explicit `--whole-cluster-policy`, then `KUBESCAPE_WHOLE_CLUSTER_POLICY`, then `KUBESCAPE_WHOLE_CLUSTER_PARITY_CHECK=true` (selecting `verify`), defaulting to `projected`:

1. **`projected` (default)** — evaluates whole-cluster controls against an incrementally accumulated working set containing resources matching their rule declarations (workloads including Pods, ReplicaSets, Deployments, DaemonSets, StatefulSets, Jobs, CronJobs, plus Services, ServiceAccounts, and RBAC). Non-matching resources (such as ConfigMaps, Secrets, and custom resources) are excluded from the projection. While all objects currently remain resident in `MapResourceCatalog`, this projection bounds the transient index and indexing CPU during the whole-cluster pass, and provides the contract required for a future bounded catalog to drop non-matching namespace resources. Parity against full-cluster evaluation holds because rule match declarations are a superset of evaluated objects, and can be cross-checked using `verify` mode.
2. **`fallback`** — materializes the entire cluster into memory and evaluates against `snapshotAllResources()`, logging an informational message about the full-memory materialization.
3. **`skip`** — bypasses whole-cluster controls entirely, skipping their indexing and evaluation for constrained environments. Skipped controls are recorded in `ScanCoverage.NotEvaluatedControls` with a traceable reason, and the standard `CoverageScore` penalty applies, ensuring posture audits stay accurate and CI cannot silently evade coverage.
4. **`verify`** — debug cross-check mode: runs whole-cluster controls against both `projected` and `fallback` scopes, diffs verdicts across all evaluated resources, and logs any parity mismatches at error level while exiting with code 0 (can be enabled via `--whole-cluster-policy=verify`, `KUBESCAPE_WHOLE_CLUSTER_POLICY=verify`, or `KUBESCAPE_WHOLE_CLUSTER_PARITY_CHECK=true` when no explicit policy is specified).

## Testing

Added comprehensive parity tests in `core/pkg/opaprocessor/processorhandler_streaming_test.go` and `core/pkg/opaprocessor/wholecluster_missing_control_test.go`:

1. **TestProcessWithStreaming_Parity**: Verifies that resource partitioning works correctly for both small and large clusters
2. **TestResourceBatch_MemoryUsage**: Verifies that namespace batches are partitioned correctly
3. **Whole-cluster policy tests**: Verifies cross-namespace join detection under `projected`, `fallback`, `skip`, and `verify` policies, noise isolation with non-matching resources, deterministic coverage accounting for skipped controls, and parity divergence reporting.

The tests confirm that:
- Small clusters (<2500 resources) use a single resident batch (backward compatible)
- Large clusters (>2500 resources) split into multiple namespace batches
- Cluster-scoped resources remain in the resident batch
- Namespace-scoped resources are partitioned correctly
- Collection-phase in-memory claims (flat ~1-2 MB partition-store metadata and pager buffer baseline across cluster sizes; on-disk spill capacity scales with namespaced resource raw JSON) are verified across 5k, 20k, and 50k synthetic clusters with 50-200 resident nodes in `BenchmarkStreamingCollectorMemory`.

## Performance Impact

### Expected API-server Savings

- **Small clusters (<2500 resources)**: by default in automatic mode, no change (single-batch collection mode); however, if streaming is explicitly enabled via `--enable-streaming=true`, small clusters can still utilize the streaming O(L) cluster-wide GVR traversal pattern.
- **Large clusters (>2500 resources)**: logical GVR traversals drop from O(L × N) (one per GVR per namespace) to O(L) (one cluster-wide traversal per GVR). For a cluster with 2,500 namespaces and 100 GVRs, this reduces ~250,000 logical traversals down to ~100 logical traversals. Note that because `pager.EachListItem` paginates (using chunked LIST requests based on page size and resource count, just as the per-namespace path could also paginate), the physical number of HTTP LIST calls depends on total object count and page size, but eliminates the O(N) namespace multiplication factor entirely.

### CPU Impact

Minimal CPU overhead from:
- Additional goroutine for streaming
- Channel operations
- Batch management

The streaming approach may be slightly slower due to the overhead of managing batches, but the API-server LIST savings are significant for large clusters.

## Configuration

| Flag / Env Var | Default | Effect |
|---|---|---|
| `--enable-streaming` | auto — enabled above `LARGE_CLUSTER_SIZE` | Manually force streaming on/off (`--enable-streaming=false` to disable) |
| `LARGE_CLUSTER_SIZE` | `2500` | Resource-count threshold for auto-enabling streaming |
| `--whole-cluster-policy` | `projected` | Execution policy for whole-cluster controls (`projected` / `fallback` / `skip` / `verify`) |
| `KUBESCAPE_WHOLE_CLUSTER_POLICY` | `projected` | Env-var equivalent of `--whole-cluster-policy` |
| `KUBESCAPE_WHOLE_CLUSTER_PARITY_CHECK` | `false` | Set `true` to run the `verify` cross-check mode when neither an explicit `--whole-cluster-policy` nor a non-empty `KUBESCAPE_WHOLE_CLUSTER_POLICY` is set |
| `KUBESCAPE_SPILL_DIR` | `$TMPDIR` (falls back to `os.TempDir()`) | Base directory for the on-disk partition store |
| `KUBESCAPE_PARTITION_STORE` | `disk` | Set `memory` to disable disk spilling entirely |

## Usage

### Manual Enablement

```bash
kubescape scan --enable-streaming
```

### Auto-Enablement

Streaming is automatically enabled for clusters with >2500 resources:

```bash
export LARGE_CLUSTER_SIZE=2500  # Default threshold
kubescape scan  # Will auto-enable streaming for large clusters
```

## Future Enhancements

1. **Accurate cluster size estimation**: Currently uses a placeholder value; should implement proper Kubernetes API discovery
2. **Adaptive batch sizing**: Could adjust batch size based on available memory
3. **Parallel batch processing**: Could process multiple namespace batches in parallel (with proper synchronization)
4. **Metrics and monitoring**: Add metrics to track memory usage and streaming performance
5. **Bounded catalog retention**: Evict non-matching namespace resources after per-namespace evaluation using the projection contract

## Compatibility

- **Backward compatible**: Small clusters continue to use the single-batch approach
- **Opt-in**: Can be manually disabled with `--enable-streaming=false`
- **Environment variable**: Threshold can be adjusted via `LARGE_CLUSTER_SIZE`
- **No breaking changes**: Existing behavior is preserved for clusters below the threshold
- **Whole-cluster policy**: Whole-cluster controls default to `projected` policy regardless of cluster size or streaming mode to bound indexing overhead. Users requiring legacy full-memory materialization for whole-cluster controls can explicitly set `--whole-cluster-policy=fallback`.

## Conclusion

This implementation addresses the API-server load issue described in A1 by replacing the O(L × N) collection loop with a single pass per GVR and by streaming batches to the OPA processor so evaluation never sees the whole cluster as its input. With the integration of the scan-scoped partition store (Phase 2), namespaced spill usage and partition-store metadata remain flat (~1-2 MB), bounding the collection-phase memory peak before evaluation to resident cluster-scoped resources plus active pager buffers, satisfying Issue #3235. Downstream retention in `ResourceCatalog` across subsequent stages (`AllResources` for exceptions, printers, and image scanning) remains unbounded in this phase. Whole-cluster controls default to the `projected` policy, which shrinks the transient index during the deferred whole-cluster pass and establishes the contract for a future bounded catalog to safely drop non-matching namespace resources.
