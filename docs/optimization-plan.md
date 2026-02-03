# Kubescape CPU/Memory Optimization Plan

**Issue:** #1793 - High CPU and Memory Usage on System-Constrained Environments  
**Date:** February 3, 2026  
**Root Cause Analysis:** Completed  
**Proposed Solution:** Combined optimization approach across multiple components

---

## Executive Summary

Investigation into issue #1793 revealed that the original worker pool proposal addressed the symptoms but not the root causes. The actual sources of resource exhaustion are:

- **Memory:** Unbounded data structures loading entire cluster state into memory
- **CPU:** Repeated expensive operations (OPA compilation) and nested loop complexity

This document outlines a phased approach to reduce memory usage by 40-60% and CPU usage by 30-50%.

---

## Root Cause Analysis

### Memory Hotspots

1. **AllResources Map** (`core/cautils/datastructures.go:53`)
   - Loads ALL Kubernetes resources into memory at once
   - No pre-sizing causes reallocations
   - Contains every pod, deployment, service, etc. in cluster
   - **Impact:** Hundreds of MBs to several GBs for large clusters

2. **ResourcesResult Map** (`core/cautils/datastructures.go:54`)
   - Stores scan results for every resource
   - Grows dynamically without capacity hints
   - **Impact:** Proportional to resources scanned

3. **Temporary Data Structures**
   - Nested loops create temporary slices in `getKubernetesObjects`
   - Repeated allocation per rule evaluation
   - **Impact:** Memory churn and GC pressure

### CPU Hotspots

1. **OPA Module Compilation** (`core/pkg/opaprocessor/processorhandler.go:324-330`)
   - Comment explicitly states: *"OPA module compilation is the most resource-intensive operation"*
   - Compiles EVERY rule from scratch (no caching)
   - Typical scan: ~100 controls × 5 rules = 500+ compilations
   - **Impact:** High CPU, repeated compilation overhead

2. **6-Level Nested Loops** (`core/pkg/opaprocessor/processorhandlerutils.go:136-167`)
   - Creates temporary data structures for each rule
   - Iterates all matched resources multiple times
   - **Impact:** O(n×m×...) complexity

3. **O(n) Slice Operations**
   - `slices.Contains()` for deduplication in image scanning
   - `RelatedResourcesIDs` slice growth with O(n) membership checks
   - **Impact:** Degraded performance with larger datasets

### Codebase Evidence

The team is already aware of this issue, with internal documentation acknowledging the problem:

```go
// isLargeCluster returns true if the cluster size is larger than the largeClusterSize
// This code is a workaround for large clusters. The final solution will be to scan resources individually
// Source: core/pkg/opaprocessor/processorhandlerutils.go:279
```

---

## Proposed Solutions: Six-Phase Implementation

### Phase 1: OPA Module Caching

**Objective:** Eliminate redundant rule compilations

**Files Modified:**
- `core/pkg/opaprocessor/processorhandler.go`
- `core/pkg/opaprocessor/processorhandler_test.go`

**Changes:**
```go
type OPAProcessor struct {
    // existing fields...
    compiledModules map[string]*ast.Compiler
    compiledMu      sync.RWMutex
}

func (opap *OPAProcessor) getCompiledRule(ctx context.Context, rule reporthandling.Rule, modules map[string]string) (*ast.Compiler, error) {
    // Check cache with read lock
    cacheKey := rule.Name + "|" + rule.Rule
    opap.compiledMu.RLock()
    if compiled, ok := opap.compiledModules[cacheKey]; ok {
        opap.compiledMu.RUnlock()
        return compiled, nil
    }
    opap.compiledMu.RUnlock()
    
    // Compile new module with write lock
    opap.compiledMu.Lock()
    defer opap.compiledMu.Unlock()
    
    // Double-check pattern (cache might have been filled)
    if compiled, ok := opap.compiledModules[cacheKey]; ok {
        return compiled, nil
    }
    
    compiled, err := ast.CompileModulesWithOpt(modules, ast.CompileOpts{
        EnablePrintStatements: opap.printEnabled,
        ParserOptions:         ast.ParserOptions{RegoVersion: ast.RegoV0},
    })
    if err != nil {
        return nil, fmt.Errorf("failed to compile rule '%s': %w", rule.Name, err)
    }
    
    opap.compiledModules[cacheKey] = compiled
    return compiled, nil
}
```

**Integration Point:** Replace direct compilation call in `runRegoOnK8s(:338` with cached retrieval

**Testing:**
- Unit test: Verify cache hit for identical rules
- Unit test: Verify cache miss for different rules
- Integration test: Measure scan time before/after

**Expected Savings:** 30-40% CPU reduction

**Risk:** Low - caching is a well-known pattern, minimal behavior change

**Dependencies:** None

---

### Phase 2: Map Pre-sizing

**Objective:** Reduce memory allocations and fragmentation

**Files Modified:**
- `core/cautils/datastructures.go`
- `core/cautils/datastructures_test.go`
- `core/pkg/resourcehandler/handlerpullresources.go`
- `core/pkg/resourcehandler/k8sresources.go`

**Changes:**

1. Update constructor to pre-size maps (cluster size estimated internally):
```go
func NewOPASessionObj(ctx context.Context, frameworks []reporthandling.Framework, k8sResources K8SResources, scanInfo *ScanInfo) *OPASessionObj {
    clusterSize := estimateClusterSize(k8sResources)
    if clusterSize < 100 {
        clusterSize = 100
    }
    return &OPASessionObj{
        AllResources:    make(map[string]workloadinterface.IMetadata, clusterSize),
        ResourcesResult: make(map[string]resourcesresults.Result, clusterSize),
        // ... other pre-sized collections
    }
}
```

2. Update resource collection to return count:
```go
func (k8sHandler *K8sResourceHandler) pullResources(queryableResources QueryableResources, ...) (K8SResources, map[string]workloadinterface.IMetadata, map[string]workloadinterface.IMetadata, map[string]map[string]bool, int, error) {
    // ... existing code ...
    return k8sResources, allResources, externalResources, excludedRulesMap, estimatedCount, nil
}
```

3. Pass size during initialization:
```go
func CollectResources(ctx context.Context, rsrcHandler IResourceHandler, opaSessionObj *cautils.OPASessionObj, ...) error {
    resourcesMap, allResources, externalResources, excludedRulesMap, estimatedCount, err := rsrcHandler.GetResources(ctx, opaSessionObj, scanInfo)
    
    // Re-initialize with proper size
    if opaSessionObj.AllResources == nil {
        opaSessionObj = cautils.NewOPASessionObj(estimatedCount)
    }
    
    opaSessionObj.K8SResources = resourcesMap
    opaSessionObj.AllResources = allResources
    // ...
}
```

**Testing:**
- Unit test: Verify pre-sized maps with expected content
- Performance test: Compare memory usage before/after
- Integration test: Scan with varying cluster sizes

**Expected Savings:** 10-20% memory reduction, reduced GC pressure

**Risk:** Low - Go's make() with capacity hint is well-tested

**Dependencies:** None

---

### Phase 3: Set-based Deduplication

**Objective:** Replace O(n) slice operations with O(1) set operations

**Files Modified:**
- `core/pkg/utils/dedup.go` (new file)
- `core/core/scan.go`
- `core/pkg/opaprocessor/processorhandler.go`

**Changes:**

1. Create new utility:
```go
// core/pkg/utils/dedup.go
package utils

import "sync"

type StringSet struct {
    items map[string]struct{}
    mu    sync.RWMutex
}

func NewStringSet() *StringSet {
    return &StringSet{
        items: make(map[string]struct{}),
    }
}

func (s *StringSet) Add(item string) {
    s.mu.Lock()
    defer s.mu.Unlock()
    s.items[item] = struct{}{}
}

func (s *StringSet) AddAll(items []string) {
    s.mu.Lock()
    defer s.mu.Unlock()
    for _, item := range items {
        s.items[item] = struct{}{}
    }
}

func (s *StringSet) Contains(item string) bool {
    s.mu.RLock()
    defer s.mu.RUnlock()
    _, ok := s.items[item]
    return ok
}

func (s *StringSet) ToSlice() []string {
    s.mu.RLock()
    defer s.mu.RUnlock()
    result := make([]string, 0, len(s.items))
    for item := range s.items {
        result = append(result, item)
    }
    return result
}
```

2. Update image scanning (`core/core/scan.go:249`):
```go
func scanImages(scanType cautils.ScanTypes, scanData *cautils.OPASessionObj, ...) {
    var imagesToScan *utils.StringSet
    imagesToScan = utils.NewStringSet()
    
    for _, workload := range scanData.AllResources {
        containers, err := workloadinterface.NewWorkloadObj(workload.GetObject()).GetContainers()
        if err != nil {
            logger.L().Error(...)
            continue
        }
        for _, container := range containers {
            if !imagesToScan.Contains(container.Image) {
                imagesToScan.Add(container.Image)
            }
        }
    }
    
    // Use imagesToScan.ToSlice() for iteration
}
```

3. Update related resources (`core/pkg/opaprocessor/processorhandler.go:261`):
```go
var relatedResourcesIDs *utils.StringSet
relatedResourcesIDs = utils.NewStringSet()

// Inside loop
if !relatedResourcesIDs.Contains(wl.GetID()) {
    relatedResourcesIDs.Add(wl.GetID())
    // ... process related resource
}
```

**Testing:**
- Unit tests for StringSet operations
- Benchmark tests comparing slice.Contains vs set.Contains
- Integration tests with real scan scenarios

**Expected Savings:** 5-10% CPU reduction for large clusters

**Risk:** Low - thread-safe set implementation, minimal behavior change

**Dependencies:** None

---

### Phase 4: Cache getKubernetesObjects

**Objective:** Eliminate repeated computation of resource groupings

**Files Modified:**
- `core/pkg/opaprocessor/processorhandler.go`
- `core/pkg/opaprocessor/processorhandlerutils.go`
- `core/pkg/opaprocessor/processorhandler_test.go`

**Changes:**

1. Add cache to processor:
```go
type OPAProcessor struct {
    // existing fields...
    k8sObjectsCache map[string]map[string][]workloadinterface.IMetadata
    k8sObjectsMu    sync.RWMutex
}
```

2. Add cache key generation:
```go
func (opap *OPAProcessor) getCacheKey(match []reporthandling.RuleMatchObjects) string {
    var strings []string
    for _, m := range match {
        for _, group := range m.APIGroups {
            for _, version := range m.APIVersions {
                for _, resource := range m.Resources {
                    strings = append(strings, fmt.Sprintf("%s/%s/%s", group, version, resource))
                }
            }
        }
    }
    sort.Strings(strings)
    return strings.Join(strings, "|")
}
```

3. Wrap getKubernetesObjects with caching:
```go
func (opap *OPAProcessor) getKubernetesObjectsCached(k8sResources cautils.K8SResources, match []reporthandling.RuleMatchObjects) map[string][]workloadinterface.IMetadata {
    cacheKey := opap.getCacheKey(match)
    
    // Try cache
    opap.k8sObjectsMu.RLock()
    if cached, ok := opap.k8sObjectsCache[cacheKey]; ok {
        opap.k8sObjectsMu.RUnlock()
        return cached
    }
    opap.k8sObjectsMu.RUnlock()
    
    // Compute new value
    result := getKubernetesObjects(k8sResources, opap.AllResources, match)
    
    // Store in cache
    opap.k8sObjectsMu.Lock()
    opap.k8sObjectsCache[cacheKey] = result
    opap.k8sObjectsMu.Unlock()
    
    return result
}
```

**Testing:**
- Unit test: Verify cache correctness
- Benchmark: Compare execution time with/without cache
- Integration test: Measure scan time on large cluster

**Expected Savings:** 10-15% CPU reduction

**Risk:** Low-Medium - needs proper cache invalidation logic (not needed as resources are static during scan)

**Dependencies:** None

---

### Phase 5: Resource Streaming

**Objective:** Process resources in batches instead of loading all at once

**Files Modified:**
- `core/pkg/resourcehandler/k8sresources.go`
- `core/pkg/resourcehandler/interface.go`
- `core/pkg/resourcehandler/filesloader.go`
- `core/pkg/opaprocessor/processorhandler.go`
- `cmd/scan/scan.go`

**Changes:**

1. Add streaming interface:
```go
// core/pkg/resourcehandler/interface.go
type IResourceHandler interface {
    GetResources(...) (...)
    StreamResources(ctx context.Context, batchSize int) (<-chan workloadinterface.IMetadata, error)
}
```

2. Implement streaming for Kubernetes resources:
```go
func (k8sHandler *K8sResourceHandler) StreamResources(ctx context.Context, batchSize int) (<-chan workloadinterface.IMetadata, error) {
    ch := make(chan workloadinterface.IMetadata, batchSize)
    
    go func() {
        defer close(ch)
        
        queryableResources := k8sHandler.getQueryableResources()
        
        for i := range queryableResources {
            select {
            case <-ctx.Done():
                return
            default:
                apiGroup, apiVersion, resource := k8sinterface.StringToResourceGroup(queryableResources[i].GroupVersionResourceTriplet)
                gvr := schema.GroupVersionResource{Group: apiGroup, Version: apiVersion, Resource: resource}
                
                result, err := k8sHandler.pullSingleResource(&gvr, nil, queryableResources[i].FieldSelectors, nil)
                if err != nil {
                    continue
                }
                
                metaObjs := ConvertMapListToMeta(k8sinterface.ConvertUnstructuredSliceToMap(result))
                
                for _, metaObj := range metaObjs {
                    select {
                    case ch <- metaObj:
                    case <-ctx.Done():
                        return
                    }
                }
            }
        }
    }()
    
    return ch, nil
}
```

3. Update OPA processor to handle streaming:
```go
func (opap *OPAProcessor) ProcessWithStreaming(ctx context.Context, policies *cautils.Policies, resourceStream <-chan workloadinterface.IMetadata, batchSize int) error {
    batch := make([]workloadinterface.IMetadata, 0, batchSize)
    opaSessionObj := cautils.NewOPASessionObj(batchSize)
    
    // Collect batch
    done := false
    for !done {
        select {
        case resource, ok := <-resourceStream:
            if !ok {
                done = true
                break
            }
            batch = append(batch, resource)
            
            if len(batch) >= batchSize {
                opaSessionObj.AllResources = batchToMap(batch)
                if err := opap.ProcessBatch(ctx, policies); err != nil {
                    return err
                }
                batch = batch[:0] // Clear batch
            }
        case <-ctx.Done():
            return ctx.Err()
        }
    }
    
    // Process remaining batch
    if len(batch) > 0 {
        opaSessionObj.AllResources = batchToMap(batch)
        if err := opap.ProcessBatch(ctx, policies); err != nil {
            return err
        }
    }
    
    return nil
}
```

4. Add CLI flags:
```go
// cmd/scan/scan.go
scanCmd.PersistentFlags().BoolVar(&scanInfo.StreamMode, "stream-resources", false, "Process resources in batches (lower memory, slightly slower)")
scanCmd.PersistentFlags().IntVar(&scanInfo.StreamBatchSize, "stream-batch-size", 100, "Batch size for resource streaming (lower = less memory)")
```

5. Auto-enable for large clusters:
```go
func shouldEnableStreaming(scanInfo *cautils.ScanInfo, estimatedClusterSize int) bool {
    if scanInfo.StreamMode {
        return true
    }
    
    largeClusterSize, _ := cautils.ParseIntEnvVar("LARGE_CLUSTER_SIZE", 2500)
    if estimatedClusterSize > largeClusterSize {
        logger.L().Info("Large cluster detected, enabling streaming mode")
        return true
    }
    
    return false
}
```

**Testing:**
- Unit test: Verify streaming produces same results as batch mode
- Performance test: Compare memory usage on large cluster
- Integration test: Test with various batch sizes
- End-to-end test: Verify scan results match existing behavior

**Expected Savings:** 30-50% memory reduction for large clusters

**Risk:** Medium - significant behavior change, needs thorough testing

**Dependencies:** Phase 2 (map pre-sizing)

---

### Phase 6: Early Cleanup

**Objective:** Free memory promptly after resources are processed

**Files Modified:**
- `core/pkg/opaprocessor/processorhandler.go`
- `core/pkg/opaprocessor/processorhandlerutils.go`

**Changes:**

```go
func (opap *OPAProcessor) Process(ctx context.Context, policies *cautils.Policies, progressListener IJobProgressNotificationClient) error {
    resourcesRemaining := make(map[string]bool)
    for id := range opap.AllResources {
        resourcesRemaining[id] = true
    }
    
    for _, toPin := range policies.Controls {
        control := toPin
        
        resourcesAssociatedControl, err := opap.processControl(ctx, &control)
        if err != nil {
            logger.L().Ctx(ctx).Warning(err.Error())
        }
        
        // Clean up processed resources if not needed for future controls
        if len(policies.Controls) > 10 && !isLargeCluster(len(opap.AllResources)) {
            for id := range resourcesAssociatedControl {
                if resourcesRemaining[id] {
                    delete(resourcesRemaining, id)
                    
                    // Remove from AllResources
                    if resource, ok := opap.AllResources[id]; ok {
                        removeData(resource)
                        delete(opap.AllResources, id)
                    }
                }
            }
        }
    }
    
    return nil
}
```

**Testing:**
- Unit test: Verify cleanup doesn't affect scan results
- Memory test: Verify memory decreases during scan
- Integration test: Test with policies that reference same resources

**Expected Savings:** 10-20% memory reduction, reduced peak memory usage

**Risk:** Medium - needs careful tracking of which resources are still needed

**Dependencies:** Phase 5 (resource streaming)

---

## Implementation Timeline

### Iteration 1 (Quick Wins)
- **Week 1:** Phase 1 - OPA Module Caching
- **Week 1:** Phase 2 - Map Pre-sizing
- **Week 2:** Phase 3 - Set-based Deduplication

### Iteration 2 (Mid-Term)
- **Week 3:** Phase 4 - Cache getKubernetesObjects

### Iteration 3 (Long-Term)
- **Weeks 4-5:** Phase 5 - Resource Streaming
- **Week 6:** Phase 6 - Early Cleanup

### Total Duration: 6 weeks

---

## Risk Assessment

| Phase | Risk Level | Mitigation Strategy |
|-------|------------|-------------------|
| 1 - OPA Caching | Low | Comprehensive unit tests, fallback to uncached mode |
| 2 - Map Pre-sizing | Low | Backward compatible, capacity hints are safe |
| 3 - Set Dedup | Low | Thread-safe implementation, comprehensive tests |
| 4 - getK8SCache | Low-Medium | Cache key validation, cache invalidation logic |
| 5 - Streaming | Medium | Feature flag (disable by default), extensive integration tests |
| 6 - Early Cleanup | Medium | Track resource dependencies, thorough validation |

---

## Performance Targets

### Memory Usage
- **Current (Large Cluster >2500 resources):** ~2-4 GB
- **Target:** ~1-2 GB (50% reduction)

### CPU Usage
- **Current:** High peaks during OPA evaluation
- **Target:** 30-50% reduction in peak CPU

### Scan Time
- **Expected:** Neutral to slight improvement (streaming may add 5-10% overhead on small clusters, large clusters benefit from reduced GC)

---

## CLI Flags (Phase 5)

```bash
# Manual streaming mode
kubescape scan framework all --stream-resources --stream-batch-size 50

# Auto-detection (default)
kubescape scan framework all  # Automatically enables streaming for large clusters

# Environment variable
export KUBESCAPE_STREAM_BATCH_SIZE=100
```

---

## Backward Compatibility

All changes are backward compatible:

1. Default behavior unchanged for small clusters (<2500 resources)
2. Streaming mode requires explicit flag or auto-detection
3. Cache changes are transparent to users
4. No breaking API changes

---

## Dependencies on External Packages

- `github.com/open-policy-agent/opa/ast` - OPA compilation (Phase 1)
- `github.com/kubescape/opa-utils` - Existing dependencies maintained

No new external dependencies required.

---

## Testing Strategy

### Unit Tests
- Each phase includes comprehensive unit tests
- Mock-based testing for components without external dependencies
- Property-based testing where applicable

### Integration Tests
- End-to-end scan validation
- Test clusters of varying sizes (100, 1000, 5000 resources)
- Validate identical results with and without optimizations

### Performance Tests
- Benchmark suite before/after each phase
- Memory profiling (pprof) for memory validation
- CPU profiling for CPU validation

### Regression Tests
- Compare scan results before/after all phases
- Validate all controls produce identical findings
- Test across different Kubernetes versions

---

## Success Criteria

1. **CPU Usage:** ≥30% reduction in peak CPU during scanning (measured with profiling)
2. **Memory Usage:** ≥40% reduction in peak memory for clusters >2500 resources
3. **Functional Correctness:** 100% of control findings identical to current implementation
4. **Scan Time:** No degradation >15% on small clusters; improvement on large clusters
5. **Stability:** Zero new race conditions or panics in production-style testing

---

## Alternative Approaches Considered

### Alternative 1: Worker Pool (Original #1793 Proposal)
- **Problem:** Addresses symptoms (concurrency) not root causes (data structures)
- **Conclusion:** Rejected - would not solve memory accumulation

### Alternative 2: Offload to Managed Service
- **Problem:** Shifts problem to infrastructure, doesn't solve core architecture
- **Conclusion:** Not appropriate for CLI tool use case

### Alternative 3: External Database for State
- **Problem:** Adds complexity, requires additional dependencies
- **Conclusion:** Overkill for single-scan operations

---

## Open Questions

1. **Cache Eviction Policy:** Should OPA module cache expire after N scans? (Current: process-scoped)
2. **Batch Size Tuning:** What default batch size balances memory vs. performance? (Proposed: 100)
3. **Early Cleanup Threshold:** What minimum control count enables early cleanup? (Proposed: 10)
4. **Large Cluster Threshold:** Keep existing 2500 or adjust based on optimization results?

---

## Recommendations

1. **Start with Phases 1-4** (low risk, good ROI) for immediate improvement
2. **Evaluate Phase 5-6** based on actual memory gains from earlier phases
3. **Add monitoring** to track real-world resource usage after deployment
4. **Consider making streaming opt-in** initially, then opt-out after validation

---

## Appendix: Key Code Locations

| Component | File | Line | Notes |
|-----------|------|------|-------|
| AllResources initialization | `core/cautils/datastructures.go` | 80-81 | Map pre-sizing target |
| OPA compilation | `core/pkg/opaprocessor/processorhandler.go` | 324-330 | Most CPU-intensive operation |
| getKubernetesObjects | `core/pkg/opaprocessor/processorhandlerutils.go` | 136-167 | 6-level nested loops |
| Resource collection | `core/pkg/resourcehandler/k8sresources.go` | 313-355 | Loads all resources |
| Image deduplication | `core/core/scan.go` | 249 | O(n) slice.Contains |
| Throttle package (unused) | `core/pkg/throttle/throttle.go` | - | Could be repurposed |

---

**Document Version:** 1.0  
**Prepared by:** Code Investigation Team  
**Review Status:** Awaiting stakeholder approval