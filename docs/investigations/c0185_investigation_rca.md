# Root Cause Analysis: C-0185 (cluster-admin role usage) Exception Flakiness on vSphere/VKS Clusters

## Executive Summary
Posture exceptions were configured for 8 subjects failing control **C-0185** (`cluster-admin-role`) across vSphere/VKS clusters running Kubescape Operator chart `1.30.6` (in-cluster scanner `v3.0.48`). The exceptions were scoped properly (`cluster: */*`, exact `resourceID`, `controlID: C-0185`), but the scanner almost never applied them, leaving the control in a `Failed` state across all 8 clusters, with intermittent non-deterministic exceptions appearing for 1–2 subjects at random.

The issue is caused by a confluence of two known bugs in Kubescape engine `v3.0.48` interacting with the Helm chart configuration on large clusters:
1. **Mid-scan bucketing threshold crossing (#2587 / commit `dd985041`)**: Dynamic mutation of `AllResources` by aggregator rules causes the cluster size to cross the `LARGE_CLUSTER_SIZE` threshold (1500) midway through scanning in random control order.
2. **Cluster-scoped resource overwriting across namespace iterations (#2311 / commit `d4a38ebd`)**: When large-cluster mode is activated, `processRule` evaluates cluster-scoped subjects once per namespace containing a `Role`, unconditionally pre-seeding the subject to `StatusPassed` in subsequent iterations, overwriting status and paths and disrupting exception application.

---

## Technical Root Cause Analysis

### 1. In-Cluster Configuration vs. Local Reproduction Discrepancy
In Helm chart `1.30.6` (`templates/kubescape/deployment.yaml`), the scanner container environment explicitly configures:
```yaml
LARGE_CLUSTER_SIZE: "1500"
```
On typical local `kind` test environments, total cluster resources number in the hundreds, well below 1500 (or the default CLI threshold of 2500). When `clusterSize <= LARGE_CLUSTER_SIZE`, `isLargeCluster` evaluates to `false`:
- All Kubernetes resources are mapped to a single synthetic namespace bucket: `clusterScope`.
- `processRule` executes exactly once for the rule against the whole cluster.
- No multi-namespace loop runs, and exceptions apply 100% of the time (explaining the 31/31 passes locally).

On production VKS clusters, total resources hover around 1,400–1,600 objects.

### 2. Mid-Scan Resource Mutation & Random Execution Order
In `v3.0.48`, `getNamespaceName(obj, len(allResources))` checked the **live** resource count:
```go
func getAllSupportedObjects(...) map[string][]workloadinterface.IMetadata {
    ...
    ns := getNamespaceName(obj, len(allResources))
    ...
}
```
In Go, iterating over the policy map `for _, toPin := range policies.Controls` executes controls in non-deterministic order.
When rules with resource aggregators execute (such as `C-0185`, `C-0188`, `C-0267`), they synthesize attack vectors/subject objects and inject them into `opap.AllResources`:
```go
opap.AllResources[inputResource.GetID()] = inputResources[i]
```
As synthetic resources are added to `AllResources`, `len(allResources)` increases mid-scan. If the initial resource count was ~1,450, `isLargeCluster` flips from `false` to `true` mid-scan depending entirely on the random control execution sequence of that specific run.

### 3. The Multi-Namespace Loop and Result Overwrites
When `isLargeCluster` is `true`, `getAllSupportedObjects` partitions objects:
- Namespaced resources (`Role`) are placed in their respective namespace buckets (`resourcesPerNS["ns-1"]`, `resourcesPerNS["ns-2"]`, ...).
- Cluster-scoped resources (`ClusterRole`, `ClusterRoleBinding`) remain in `resourcesPerNS[clusterScope]`.

`processRule` then executes the namespace loop:
```go
for i := range resourcesPerNS {
    resourceToScan := resourcesPerNS[i]
    if _, ok := resourcesPerNS[clusterScope]; ok && i != clusterScope {
        resourceToScan = append(resourceToScan, resourcesPerNS[clusterScope]...)
    }
    inputResources, err := reporthandling.RegoResourcesAggregator(rule, resourceToScan)
    ...
    for i, inputResource := range inputResources {
        if opap.skipNamespace(inputResource.GetNamespace()) { continue }
        resources[inputResource.GetID()] = &resourcesresults.ResourceAssociatedRule{
            Name:                  rule.Name,
            ControlConfigurations: ruleRegoDependenciesData.PostureControlInputs,
            Status:                apis.StatusPassed, // PRE-SEEDED AS PASSED!
        }
        opap.AllResources[inputResource.GetID()] = inputResources[i]
    }
    ...
}
```

Notice what happens for **C-0185** (`cluster-admin-role`):
- Its `Match` criteria includes:
  `Resources: ["Role", "ClusterRole", "ClusterRoleBinding"]`
- Because `Role` is namespaced, `resourcesPerNS` creates an entry for **every namespace that contains a `Role`**.
- In every namespace iteration `i`, `resourceToScan` includes that namespace's `Role`s **plus all cluster-scoped objects** (`ClusterRole` cluster-admin and `ClusterRoleBinding` cluster-admin).
- `AggregateResourcesBySubjects` pairs the `ClusterRoleBinding` and `ClusterRole`, outputting the exact same 8 subject vectors into `inputResources` on **every single namespace iteration**.
- In `v3.0.48`, the pre-seed loop runs on every namespace iteration. When iteration $N+1$ runs, it unconditionally overwrites `resources[subjectID]` back to `StatusPassed`, clearing out failures or mutating references.
- In `updateResults`, exception matching runs against `ResourcesResult`. Because of the broken intermediate state, corrupted paths, or iteration ordering in `resourcesPerNS` (which is also a Go map), exceptions fail to apply or the control status calculation fails to flip from Failed to Skipped/Passed.

### 4. Why C-0188 Behave Differently
- **C-0188** (`rule-can-create-pod`) matches `Role`, `ClusterRole`, `RoleBinding`, and `ClusterRoleBinding`. It evaluates specific pod-creation rules in `Role` / `RoleBinding` pairs within each namespace.
- **C-0185** matches `Role` only to inspect possible roles, but the actual violation is cluster-wide (`role.metadata.name == "cluster-admin"` and `rolebinding.kind == "ClusterRoleBinding"`). Aggregating purely cluster-scoped subjects inside a per-namespace loop causes redundant evaluations and state collisions that C-0188 does not suffer from in the same manner.

### 5. Why Prod-EU Was Not Affected
`prod-eu` clusters had resource counts either well below 1,500 (meaning `isLargeCluster` remained `false` throughout) or had different namespace/RBAC distributions where the conflict did not manifest.

---

## Resolution & Fixes

### Permanent Fix: Upgrading
This issue was resolved in upstream Kubescape across two commits:
1. **Commit `d4a38ebd` (#2311)**: *fix(opaprocessor): preserve cluster-scoped paths across namespace iterations*
   - Avoids unconditionally overwriting cluster-scoped resource results in `processRule` during namespace iterations.
2. **Commit `dd985041` (#2587)**: *[fix]: non-deterministic namespace bucketing caused by mid-scan resource count mutation*
   - Freezes `initialResourceCount` at OPAProcessor construction time so the large-cluster decision never drifts mid-scan.

**Upgrade Target**:
- Upgrade to Kubescape Operator chart **>= 1.31.0** (or any version embedding Kubescape engine **>= v3.0.52**).

---

## Immediate Workaround (Zero-Downtime, No Chart Upgrade Required)
If upgrading the operator is blocked by maintenance windows or testing requirements, users can immediately resolve the issue by raising `LARGE_CLUSTER_SIZE` in their existing Helm release values.

In the values file for `kubescape-operator` (chart 1.30.6):
```yaml
kubescape:
  env:
    - name: LARGE_CLUSTER_SIZE
      value: "10000"
```
*(Or specify `--set kubescape.env[0].name=LARGE_CLUSTER_SIZE,kubescape.env[0].value="10000"`)*

### Why This Workaround Works
Setting `LARGE_CLUSTER_SIZE: "10000"` ensures `isLargeCluster` evaluates to `false` for the entire duration of the scan. All RBAC resources will be evaluated in a single batch (`clusterScope`), identical to the test environment, completely bypassing the buggy multi-namespace loop. All 8 exceptions will apply reliably on 100% of scans immediately.
