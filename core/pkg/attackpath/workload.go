package attackpath

import (
	"fmt"
	"maps"
	"slices"

	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v4/core/pkg/networkpolicy"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
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

// isSupportedWorkloadResource excludes custom resources that reuse a built-in
// kind name. Versions may differ, but the API group must match the supported GVR.
func isSupportedWorkloadResource(r workloadinterface.IMetadata) bool {
	if r == nil {
		return false
	}
	gvr, supported := WorkloadKindGVRs[r.GetKind()]
	if !supported {
		return false
	}
	apiVersion, ok := r.GetObject()["apiVersion"].(string)
	if !ok {
		return false
	}
	gv, err := schema.ParseGroupVersion(apiVersion)
	return err == nil && gv.Version != "" && gv.Group == gvr.Group
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
	labels, _ := podTemplateLabelsChecked(kind, obj)
	return labels
}

func podTemplateLabelsChecked(kind string, obj map[string]any) (map[string]string, error) {
	path := []string{"spec", "template", "metadata", "labels"}
	if kind == "Pod" {
		path = []string{"metadata", "labels"}
	}
	if kind == "CronJob" {
		path = []string{"spec", "jobTemplate", "spec", "template", "metadata", "labels"}
	}
	raw, found, err := unstructured.NestedFieldNoCopy(obj, path...)
	if err != nil {
		return nil, err
	}
	if !found || raw == nil {
		return nil, nil
	}
	labels, _, err := unstructured.NestedStringMap(obj, path...)
	return labels, err
}

// PodTemplateHostNetwork extracts the hostNetwork field from a workload's
// pod spec. A Pod running with hostNetwork: true uses the node's network
// namespace and gets ExposureOpen regardless of NetworkPolicy rules.
// Exported so cmd/mcpserver can call it alongside PodTemplateLabels.
func PodTemplateHostNetwork(kind string, obj map[string]any) bool {
	hostNetwork, _ := podTemplateHostNetworkChecked(kind, obj)
	return hostNetwork
}

func podTemplateHostNetworkChecked(kind string, obj map[string]any) (bool, error) {
	path := []string{"spec", "template", "spec", "hostNetwork"}
	if kind == "Pod" {
		path = []string{"spec", "hostNetwork"}
	}
	if kind == "CronJob" {
		path = []string{"spec", "jobTemplate", "spec", "template", "spec", "hostNetwork"}
	}
	raw, found, err := unstructured.NestedFieldNoCopy(obj, path...)
	if err != nil {
		return false, err
	}
	if !found || raw == nil {
		return false, nil
	}
	value, ok := raw.(bool)
	if !ok {
		return false, fmt.Errorf("hostNetwork is not a boolean")
	}
	return value, nil
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
	// Build a lookup of decoded endpoint data by namespace/kind/name.
	type endpointData struct {
		labels      map[string]string
		hostNetwork bool
		malformed   bool
	}
	lookup := make(map[string]endpointData, len(resources))
	ambiguous := make(map[string]bool)
	for _, r := range resources {
		if !isSupportedWorkloadResource(r) {
			continue
		}
		key := r.GetNamespace() + "/" + r.GetKind() + "/" + r.GetName()

		labels, labelsErr := podTemplateLabelsChecked(r.GetKind(), r.GetObject())
		hostNetwork, hostErr := podTemplateHostNetworkChecked(r.GetKind(), r.GetObject())
		data := endpointData{labels: labels, hostNetwork: hostNetwork, malformed: labelsErr != nil || hostErr != nil}
		if previous, exists := lookup[key]; exists {
			data.malformed = data.malformed || previous.malformed
			// Missing controller template labels prevent resolution, but a Pod's
			// omitted labels and explicit empty labels are the same label set.
			if (r.GetKind() != "Pod" && (previous.labels == nil) != (labels == nil)) ||
				!maps.Equal(previous.labels, labels) || previous.hostNetwork != hostNetwork {
				ambiguous[key] = true
			}
		}
		lookup[key] = data
	}

	// Sort refs for deterministic output.
	sorted := slices.SortedFunc(slices.Values(refs), func(a, b WorkloadRef) int {
		if a.Namespace != b.Namespace {
			if a.Namespace < b.Namespace {
				return -1
			}
			return 1
		}
		if a.Kind != b.Kind {
			if a.Kind < b.Kind {
				return -1
			}
			return 1
		}
		if a.Name < b.Name {
			return -1
		}
		if a.Name > b.Name {
			return 1
		}
		return 0
	})

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
		if ambiguous[key] {
			results = append(results, WorkloadEndpointResult{
				Ref:    ref,
				Reason: fmt.Sprintf("%s %s/%s: conflicting endpoint data in collected manifests", ref.Kind, ref.Namespace, ref.Name),
			})
			continue
		}
		data, ok := lookup[key]
		if !ok {
			results = append(results, WorkloadEndpointResult{
				Ref:    ref,
				Reason: fmt.Sprintf("%s %s/%s not found in collected resources", ref.Kind, ref.Namespace, ref.Name),
			})
			continue
		}
		if data.malformed {
			results = append(results, WorkloadEndpointResult{Ref: ref, Reason: fmt.Sprintf("%s %s/%s: pod labels or hostNetwork could not be decoded", ref.Kind, ref.Namespace, ref.Name)})
			continue
		}
		labels := data.labels
		// nil labels on a non-Pod workload means no pod template found
		// (e.g. a selector-less Job). Report it as skipped, not guessed.
		if labels == nil && ref.Kind != "Pod" {
			results = append(results, WorkloadEndpointResult{
				Ref:    ref,
				Reason: fmt.Sprintf("%s %s/%s: pod template labels not found", ref.Kind, ref.Namespace, ref.Name),
			})
			continue
		}
		// Endpoint.Name identifies a concrete Pod for Reaches' self-access
		// shortcut. A controller represents multiple Pods, not one Pod; its
		// identity remains in Ref and must not bypass policy evaluation.
		podName := ""
		if ref.Kind == "Pod" {
			podName = ref.Name
		}
		results = append(results, WorkloadEndpointResult{
			Ref: ref,
			Endpoint: networkpolicy.Endpoint{
				Namespace:   ref.Namespace,
				Name:        podName,
				Labels:      labels,
				HostNetwork: data.hostNetwork,
			},
			Resolved: true,
		})
	}
	return results
}
