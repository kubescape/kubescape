package attackpath

import (
    "fmt"
    "maps"
    "slices"

    "github.com/kubescape/k8s-interface/workloadinterface"
    corev1 "k8s.io/api/core/v1"
    "k8s.io/apimachinery/pkg/runtime/schema"
    "k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
    "github.com/kubescape/kubescape/v4/core/pkg/networkpolicy"
)

// WorkloadKindGVRs maps every workload kind this package knows how to
// resolve pod-template labels for to its GVR. Kinds outside this map are
// reported as skipped rather than guessed at.
// Exported so cmd/mcpserver can reference it and drop its own copy.
var WorkloadKindGVRs = map[string]schema.GroupVersionResource{
    "Pod":         {Group: "", Version: "v1", Resource: "pods"},
    "Deployment":  {Group: "apps", Version: "v1", Resource: "deployments"},
    "StatefulSet": {Group: "apps", Version: "v1", Resource: "statefulsets"},
    "DaemonSet":   {Group: "apps", Version: "v1", Resource: "daemonsets"},
    "ReplicaSet":  {Group: "apps", Version: "v1", Resource: "replicasets"},
    "Job":         {Group: "batch", Version: "v1", Resource: "jobs"},
    "CronJob":     {Group: "batch", Version: "v1", Resource: "cronjobs"},
}

// WorkloadRef identifies one workload in the collected resource map.
type WorkloadRef struct {
    Namespace string
    Kind      string
    Name      string
}

// PodTemplateLabels extracts the labels a NetworkPolicy's podSelector
// matches against from a workload object's generic representation:
// a Pod's own metadata.labels, or (for controller kinds) the pod
// template's labels. Exported so cmd/mcpserver can call it directly.
// Returns nil when the path cannot be found (selector-less or headless).
func PodTemplateLabels(kind string, obj map[string]any) map[string]string {
    u := &unstructured.Unstructured{Object: obj}
    if kind == "Pod" {
        return u.GetLabels()
    }
    path := []string{"spec", "template", "metadata", "labels"}
    if kind == "CronJob" {
        path = []string{"spec", "jobTemplate", "spec", "template", "metadata", "labels"}
    }
    raw, found, err := unstructured.NestedStringMap(u.Object, path...)
    if err != nil || !found {
        return nil
    }
    return raw
}

// WorkloadEndpointResult is the outcome of resolving one workload to its
// network identity from the static resource map.
type WorkloadEndpointResult struct {
    Ref      WorkloadRef
    Endpoint networkpolicy.Endpoint // valid when Resolved == true
    Resolved bool
    // Reason is why Resolved is false (unknown kind, not in resources, no labels).
    Reason string
}

// ResolveEndpointsFromResources resolves every workload in refs to a
// networkpolicy.Endpoint using the static resource map collected by the
// scanner, visiting refs in sorted order for determinism.
// A workload whose kind is not in WorkloadKindGVRs, or whose object is
// absent from resources, or whose pod-template labels are nil, is marked
// Resolved=false with a Reason; it is never guessed at.
func ResolveEndpointsFromResources(
    resources map[string]workloadinterface.IMetadata,
    refs []WorkloadRef,
) []WorkloadEndpointResult {
    // Build a lookup: "namespace/kind/name" → IMetadata
    lookup := make(map[string]workloadinterface.IMetadata, len(resources))
    for _, r := range resources {
        if r == nil {
            continue
        }
        key := r.GetNamespace() + "/" + r.GetKind() + "/" + r.GetName()
        lookup[key] = r
    }

    // Sort refs for deterministic output.
    sorted := slices.SortedFunc(slices.Values(refs), func(a, b WorkloadRef) int {
        if a.Namespace != b.Namespace {
            if a.Namespace < b.Namespace { return -1 }
            return 1
        }
        if a.Kind != b.Kind {
            if a.Kind < b.Kind { return -1 }
            return 1
        }
        if a.Name < b.Name { return -1 }
        if a.Name > b.Name { return 1 }
        return 0
    })
    _ = maps.Keys // keep import used

    results := make([]WorkloadEndpointResult, 0, len(sorted))
    for _, ref := range sorted {
        if _, known := WorkloadKindGVRs[ref.Kind]; !known {
            results = append(results, WorkloadEndpointResult{
                Ref:    ref,
                Reason: fmt.Sprintf("kind %q is not a resolvable workload kind", ref.Kind),
            })
            continue
        }
        key := ref.Namespace + "/" + ref.Kind + "/" + ref.Name
        r, ok := lookup[key]
        if !ok {
            results = append(results, WorkloadEndpointResult{
                Ref:    ref,
                Reason: fmt.Sprintf("%s %s/%s not found in collected resources", ref.Kind, ref.Namespace, ref.Name),
            })
            continue
        }
        labels := PodTemplateLabels(ref.Kind, r.GetObject())
        // nil labels on a non-Pod workload means no pod template found
        // (e.g. a selector-less Job). Report it as skipped, not guessed.
        if labels == nil && ref.Kind != "Pod" {
            results = append(results, WorkloadEndpointResult{
                Ref:    ref,
                Reason: fmt.Sprintf("%s %s/%s: pod template labels not found", ref.Kind, ref.Namespace, ref.Name),
            })
            continue
        }
        results = append(results, WorkloadEndpointResult{
            Ref:      ref,
            Endpoint: networkpolicy.Endpoint{Namespace: ref.Namespace, Name: ref.Name, Labels: labels},
            Resolved: true,
        })
    }
    return results
}
