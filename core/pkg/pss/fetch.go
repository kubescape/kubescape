// Package pss fetch provides cluster workload listing and deduplication
// utilities shared by both the MCP predict_pss_compliance tool and the
// kubescape predict pss CLI command.
package pss

import (
	"context"
	"fmt"
	"slices"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic"
)

// WorkloadTarget maps a GVR to its corresponding Kind string, used by
// FetchNamespaceWorkloads to know which resource types to list.
type WorkloadTarget struct {
	GVR  schema.GroupVersionResource
	Kind string
}

// DefaultWorkloadTargets is the standard set of workload types evaluated
// for PSS compliance. The MCP tool and CLI both use this list.
var DefaultWorkloadTargets = []WorkloadTarget{
	{GVR: schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "deployments"}, Kind: "Deployment"},
	{GVR: schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "daemonsets"}, Kind: "DaemonSet"},
	{GVR: schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "statefulsets"}, Kind: "StatefulSet"},
	{GVR: schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "replicasets"}, Kind: "ReplicaSet"},
	{GVR: schema.GroupVersionResource{Group: "batch", Version: "v1", Resource: "jobs"}, Kind: "Job"},
	{GVR: schema.GroupVersionResource{Group: "batch", Version: "v1", Resource: "cronjobs"}, Kind: "CronJob"},
	{GVR: schema.GroupVersionResource{Group: "", Version: "v1", Resource: "pods"}, Kind: "Pod"},
}

// SupportedKinds returns the set of Kind strings from DefaultWorkloadTargets,
// useful for filtering local manifests to only supported workload types.
func SupportedKinds() map[string]bool {
	m := make(map[string]bool, len(DefaultWorkloadTargets))
	for _, t := range DefaultWorkloadTargets {
		m[t.Kind] = true
	}
	return m
}

// FilterTargetsByKind returns the subset of targets whose Kind matches
// (case-insensitive). Returns nil if no match is found.
func FilterTargetsByKind(targets []WorkloadTarget, kind string) []WorkloadTarget {
	for _, t := range targets {
		if strings.EqualFold(t.Kind, kind) {
			return []WorkloadTarget{t}
		}
	}
	return nil
}

// ListResourceError records a failure to list objects of a specific kind.
type ListResourceError struct {
	GVR  schema.GroupVersionResource
	Kind string
	Err  error
}

func (e *ListResourceError) Error() string {
	return fmt.Sprintf("failed to list %s objects: %v", e.Kind, e.Err)
}

func (e *ListResourceError) Unwrap() error {
	return e.Err
}

// FetchNamespaceWorkloads lists all workloads of the given target types in
// the specified namespace using the dynamic client. Each returned object has
// its Kind set (the Kubernetes API omits it from list responses).
func FetchNamespaceWorkloads(ctx context.Context, dynClient dynamic.Interface, namespace string, targets []WorkloadTarget) ([]unstructured.Unstructured, error) {
	var all []unstructured.Unstructured
	for _, target := range targets {
		items, err := fetchWorkloadPages(ctx, dynClient, namespace, target)
		if err != nil {
			return nil, &ListResourceError{GVR: target.GVR, Kind: target.Kind, Err: err}
		}
		all = append(all, items...)
	}
	return all, nil
}

const workloadListPageSize int64 = 500
const maxWorkloadListPages = 1000

// fetchWorkloadPages follows the server's opaque continuation token. A failed
// or cyclic listing is an error, never a successful partial compliance scan.
func fetchWorkloadPages(ctx context.Context, client dynamic.Interface, namespace string, target WorkloadTarget) ([]unstructured.Unstructured, error) {
	var items []unstructured.Unstructured
	options := metav1.ListOptions{Limit: workloadListPageSize}
	seen := make(map[string]struct{})
	for page := 0; page < maxWorkloadListPages; page++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		list, err := client.Resource(target.GVR).Namespace(namespace).List(ctx, options)
		if err != nil {
			return nil, err
		}
		if list == nil {
			return nil, fmt.Errorf("workload listing returned a nil list")
		}
		for i := range list.Items {
			if list.Items[i].GetKind() == "" {
				list.Items[i].SetKind(target.Kind)
			}
		}
		items = append(items, list.Items...)
		next := list.GetContinue()
		if next == "" {
			return items, nil
		}
		if _, duplicate := seen[next]; duplicate {
			return nil, fmt.Errorf("workload listing repeated a continuation token")
		}
		seen[next] = struct{}{}
		options.Continue = next
	}
	return nil, fmt.Errorf("workload listing exceeded the %d-page safety limit", maxWorkloadListPages)
}

// DeduplicateWorkloads filters workloads for namespace-wide scans, removing
// child workloads (e.g., ReplicaSets and Pods) only when an evaluated
// supported ancestor actually represents the workload. Custom-owned workloads
// (e.g., Deployments or Pods managed by CRD operators) and workloads whose
// controller owners are absent from the scan are retained as roots. Children
// with different PSS violations, or whose PodSpec cannot be decoded, are kept
// even when their owner is present; ownership alone does not prove the current
// template represents an old revision or an admission-mutated Pod.
func DeduplicateWorkloads(workloads []unstructured.Unstructured) []unstructured.Unstructured {
	byUID := make(map[types.UID]int, len(workloads))
	byKindName := make(map[string]int, len(workloads))

	for i, w := range workloads {
		if uid := w.GetUID(); uid != "" {
			byUID[uid] = i
		}
		key := fmt.Sprintf("%s/%s/%s", w.GetNamespace(), strings.ToLower(w.GetKind()), w.GetName())
		byKindName[key] = i
	}

	// Compare all checks, even when the caller requests Baseline, so a
	// distinct Restricted violation cannot disappear behind a parent either.
	type evaluation struct {
		violations []Violation
		err        error
	}
	evaluations := make([]evaluation, len(workloads))
	for i, w := range workloads {
		evaluations[i].violations, evaluations[i].err = EvaluateUnstructured(w.GetKind(), w.Object, Restricted)
	}
	equivalent := func(a, b int) bool {
		return evaluations[a].err == nil && evaluations[b].err == nil &&
			slices.Equal(evaluations[a].violations, evaluations[b].violations)
	}

	var selected []unstructured.Unstructured
	for i, w := range workloads {
		if hasEvaluatedAncestor(i, workloads, byUID, byKindName, equivalent) {
			continue
		}
		selected = append(selected, w)
	}
	return selected
}

// getControllerRef returns the controller owner reference for an unstructured
// object, or nil if the object has no controller owner.
func getControllerRef(obj unstructured.Unstructured) *metav1.OwnerReference {
	for _, ref := range obj.GetOwnerReferences() {
		if ref.Controller != nil && *ref.Controller {
			r := ref
			return &r
		}
	}
	return nil
}

// findParentInWorkloads looks up a controller owner reference in the
// workload indices. It first tries UID-based lookup, then falls back to
// namespace/kind/name-based lookup with UID cross-validation when available.
// All supported workloads are namespaced: an owner in a different namespace
// cannot represent this child's evaluation, even if a stale UID matches.
func findParentInWorkloads(ref metav1.OwnerReference, namespace string, workloads []unstructured.Unstructured, byUID map[types.UID]int, byKindName map[string]int) (int, bool) {
	if ref.UID != "" {
		if idx, ok := byUID[ref.UID]; ok {
			if workloads[idx].GetNamespace() == namespace && strings.EqualFold(workloads[idx].GetKind(), ref.Kind) {
				return idx, true
			}
		}
	}
	key := fmt.Sprintf("%s/%s/%s", namespace, strings.ToLower(ref.Kind), ref.Name)
	if idx, ok := byKindName[key]; ok {
		parent := workloads[idx]
		if ref.UID != "" && parent.GetUID() != "" && ref.UID != parent.GetUID() {
			return -1, false
		}
		return idx, true
	}
	return -1, false
}

// hasEvaluatedAncestor drops a workload only when a collected ancestor has
// the same PSS result. Old revisions and admission-mutated children can differ
// from a controller's current template and must then be evaluated themselves.
func hasEvaluatedAncestor(idx int, workloads []unstructured.Unstructured, byUID map[types.UID]int, byKindName map[string]int, equivalent func(int, int) bool) bool {
	visited := make(map[int]int)
	var path []int
	cycleIncludesStart := false

	curr := idx
	for {
		if step, seen := visited[curr]; seen {
			cycleIncludesStart = step == 0
			break
		}
		visited[curr] = len(path)
		path = append(path, curr)
		ref := getControllerRef(workloads[curr])
		if ref == nil {
			break
		}
		parentIdx, found := findParentInWorkloads(*ref, workloads[curr].GetNamespace(), workloads, byUID, byKindName)
		if !found {
			break
		}
		curr = parentIdx
	}

	for _, ancestor := range path[1:] {
		// Inside an owner cycle, retain the lowest index for each distinct
		// result, rather than allowing equivalent members to drop each other.
		if cycleIncludesStart && ancestor > idx {
			continue
		}
		if equivalent(idx, ancestor) {
			return true
		}
	}
	return false
}
