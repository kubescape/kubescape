// Package pss fetch provides cluster workload listing and deduplication
// utilities shared by both the MCP predict_pss_compliance tool and the
// kubescape predict pss CLI command.
package pss

import (
	"context"
	"fmt"
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
		list, err := dynClient.Resource(target.GVR).Namespace(namespace).List(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, &ListResourceError{GVR: target.GVR, Kind: target.Kind, Err: err}
		}
		for i := range list.Items {
			if list.Items[i].GetKind() == "" {
				list.Items[i].SetKind(target.Kind)
			}
			all = append(all, list.Items[i])
		}
	}
	return all, nil
}

// DeduplicateWorkloads filters workloads for namespace-wide scans, removing
// child workloads (e.g., ReplicaSets and Pods) only when an evaluated
// supported ancestor actually represents the workload. Custom-owned workloads
// (e.g., Deployments or Pods managed by CRD operators) and workloads whose
// controller owners are absent from the scan are retained as roots.
func DeduplicateWorkloads(workloads []unstructured.Unstructured) []unstructured.Unstructured {
	byUID := make(map[types.UID]int, len(workloads))
	byKindName := make(map[string]int, len(workloads))

	for i, w := range workloads {
		if uid := w.GetUID(); uid != "" {
			byUID[uid] = i
		}
		key := fmt.Sprintf("%s/%s", strings.ToLower(w.GetKind()), w.GetName())
		byKindName[key] = i
	}

	var selected []unstructured.Unstructured
	for i, w := range workloads {
		if hasEvaluatedAncestor(i, workloads, byUID, byKindName) {
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
// kind/name-based lookup with UID cross-validation when available.
func findParentInWorkloads(ref metav1.OwnerReference, workloads []unstructured.Unstructured, byUID map[types.UID]int, byKindName map[string]int) (int, bool) {
	if ref.UID != "" {
		if idx, ok := byUID[ref.UID]; ok {
			if strings.EqualFold(workloads[idx].GetKind(), ref.Kind) {
				return idx, true
			}
		}
	}
	key := fmt.Sprintf("%s/%s", strings.ToLower(ref.Kind), ref.Name)
	if idx, ok := byKindName[key]; ok {
		parent := workloads[idx]
		if ref.UID != "" && parent.GetUID() != "" && ref.UID != parent.GetUID() {
			return -1, false
		}
		return idx, true
	}
	return -1, false
}

// hasEvaluatedAncestor walks the controller-owner chain starting at
// workloads[idx] and returns true if an ancestor in the workloads slice
// would be evaluated in its place (meaning idx should be skipped).
func hasEvaluatedAncestor(idx int, workloads []unstructured.Unstructured, byUID map[types.UID]int, byKindName map[string]int) bool {
	visited := make(map[int]int) // workload index -> step in traversal path
	var path []int

	curr := idx
	for {
		if step, seen := visited[curr]; seen {
			// Cycle detected in ancestor chain. Designate the lowest index in the cycle
			// as the evaluated root so that cyclic workloads are not dropped entirely.
			cycle := path[step:]
			minIdx := cycle[0]
			for _, c := range cycle[1:] {
				if c < minIdx {
					minIdx = c
				}
			}
			return idx != minIdx
		}

		visited[curr] = len(path)
		path = append(path, curr)

		ref := getControllerRef(workloads[curr])
		if ref == nil {
			// No controller parent. If curr != idx, curr is the evaluated root ancestor.
			return curr != idx
		}

		parentIdx, found := findParentInWorkloads(*ref, workloads, byUID, byKindName)
		if !found {
			// Controller parent is an unsupported kind (custom resource) or absent from the scan.
			// If curr != idx, curr is the evaluated root ancestor.
			return curr != idx
		}

		curr = parentIdx
	}
}
