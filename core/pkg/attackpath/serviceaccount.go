package attackpath

import (
	"slices"

	"github.com/kubescape/k8s-interface/workloadinterface"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// ServiceAccountBinding records which ServiceAccount a workload runs as,
// and whether the token is actually mounted (which determines whether
// compromising the workload yields a usable token).
type ServiceAccountBinding struct {
	WorkloadRef WorkloadRef
	// ServiceAccountName is the resolved serviceAccountName.
	// Empty means "default" per Kubernetes semantics.
	ServiceAccountName string
	// Namespace is the workload's namespace; the SA is always in the same one.
	Namespace string
	// TokenMounted is true when a service account token is actually mounted
	// into the pod. When false, compromising the workload does not yield a
	// usable token (no runs-as edge). The logic follows the Kubernetes spec:
	//   1. If a projected serviceAccountToken volume is present → true,
	//      regardless of automountServiceAccountToken values (the token is
	//      explicitly requested).
	//   2. Otherwise, the pod-level automountServiceAccountToken wins if set.
	//   3. Otherwise, the SA-level automountServiceAccountToken applies
	//      (assumed true when not set, matching the Kubernetes default).
	// The proposal §7 golden-file cases are exactly this logic.
	TokenMounted bool
	// Skipped is true when the workload's object could not be decoded for
	// SA resolution (kind not in WorkloadKindGVRs, missing from resources).
	Skipped    bool
	SkipReason string
}

// saPath is the pod-template field path to spec.serviceAccountName.
// For non-CronJob controllers this is spec.template.spec.serviceAccountName;
// for CronJob it is one level deeper.
func saPath(kind string) []string {
	if kind == "Pod" {
		return []string{"spec", "serviceAccountName"}
	}
	if kind == "CronJob" {
		return []string{"spec", "jobTemplate", "spec", "template", "spec", "serviceAccountName"}
	}
	return []string{"spec", "template", "spec", "serviceAccountName"}
}

func automountPath(kind string) []string {
	if kind == "Pod" {
		return []string{"spec", "automountServiceAccountToken"}
	}
	if kind == "CronJob" {
		return []string{"spec", "jobTemplate", "spec", "template", "spec", "automountServiceAccountToken"}
	}
	return []string{"spec", "template", "spec", "automountServiceAccountToken"}
}

func volumesPath(kind string) []string {
	if kind == "Pod" {
		return []string{"spec", "volumes"}
	}
	if kind == "CronJob" {
		return []string{"spec", "jobTemplate", "spec", "template", "spec", "volumes"}
	}
	return []string{"spec", "template", "spec", "volumes"}
}

// hasProjectedServiceAccountToken reports whether the pod spec contains
// a projected volume of type serviceAccountToken, meaning the token is
// explicitly mounted regardless of automountServiceAccountToken settings.
// containersFieldPath returns the path to the containers array in a workload's pod spec.
func containersFieldPath(kind string) []string {
	if kind == "Pod" {
		return []string{"spec", "containers"}
	}
	if kind == "CronJob" {
		return []string{"spec", "jobTemplate", "spec", "template", "spec", "containers"}
	}
	return []string{"spec", "template", "spec", "containers"}
}

// hasProjectedServiceAccountToken reports whether the pod spec contains
// a projected serviceAccountToken volume that is actually mounted by at
// least one container. A declared but unmounted volume does not expose
// the token to any container process.
func hasProjectedServiceAccountToken(obj map[string]any, kind string) bool {
	u := &unstructured.Unstructured{Object: obj}

	// Step 1: collect names of volumes that carry a projected serviceAccountToken.
	vols, found, err := unstructured.NestedSlice(u.Object, volumesPath(kind)...)
	if err != nil || !found {
		return false
	}
	projectedVolNames := map[string]bool{}
	for _, v := range vols {
		vol, ok := v.(map[string]any)
		if !ok {
			continue
		}
		name, _ := vol["name"].(string)
		projected, ok := vol["projected"].(map[string]any)
		if !ok {
			continue
		}
		sources, ok := projected["sources"].([]any)
		if !ok {
			continue
		}
		for _, s := range sources {
			src, ok := s.(map[string]any)
			if !ok {
				continue
			}
			if _, has := src["serviceAccountToken"]; has {
				projectedVolNames[name] = true
			}
		}
	}
	if len(projectedVolNames) == 0 {
		return false
	}

	// Step 2: confirm at least one container mounts one of those volumes.
	// A declared but unmounted volume does not expose its token.
	containers, found, err := unstructured.NestedSlice(u.Object, containersFieldPath(kind)...)
	if err != nil || !found {
		// No containers field: conservatively treat declaration as mounted
		// (errs toward over-reporting, never under-reporting).
		return true
	}
	for _, c := range containers {
		container, ok := c.(map[string]any)
		if !ok {
			continue
		}
		mounts, _, _ := unstructured.NestedSlice(container, "volumeMounts")
		for _, m := range mounts {
			mount, ok := m.(map[string]any)
			if !ok {
				continue
			}
			mountName, _ := mount["name"].(string)
			if projectedVolNames[mountName] {
				return true
			}
		}
	}
	return false
}

// ResolveServiceAccountBindings resolves every workload in the resource
// map to its ServiceAccount and token-mount status, in resource-ID order
// for determinism.
// saAutomountByNsName is a map of "namespace/name" → *bool reflecting
// each ServiceAccount's own automountServiceAccountToken setting;
// a missing key or nil pointer is treated as the Kubernetes default (true).
func ResolveServiceAccountBindings(
	resources map[string]workloadinterface.IMetadata,
	saAutomountByNsName map[string]*bool,
) []ServiceAccountBinding {
	// Collect workload resources (kinds we know about) in ID order.
	type entry struct {
		id  string
		res workloadinterface.IMetadata
	}
	var entries []entry
	for id, r := range resources {
		if r == nil {
			continue
		}
		if _, ok := WorkloadKindGVRs[r.GetKind()]; !ok {
			continue
		}
		entries = append(entries, entry{id: id, res: r})
	}
	// Sort by ID for determinism (mirrors rbacgraph.FromResources).
	slices.SortFunc(entries, func(a, b entry) int {
		if a.id < b.id {
			return -1
		}
		if a.id > b.id {
			return 1
		}
		return 0
	})

	var out []ServiceAccountBinding
	for _, e := range entries {
		r := e.res
		ref := WorkloadRef{Namespace: r.GetNamespace(), Kind: r.GetKind(), Name: r.GetName()}
		obj := r.GetObject()
		u := &unstructured.Unstructured{Object: obj}

		saName, _, _ := unstructured.NestedString(u.Object, saPath(r.GetKind())...)
		if saName == "" {
			saName = "default"
		}

		// Determine token mount status per the three-level logic above.
		tokenMounted := false
		if hasProjectedServiceAccountToken(obj, r.GetKind()) {
			// Explicit projected volume: token is mounted unconditionally.
			tokenMounted = true
		} else {
			// Check pod-level automountServiceAccountToken.
			podVal, podFound, _ := unstructured.NestedFieldNoCopy(u.Object, automountPath(r.GetKind())...)
			if podFound {
				if b, ok := podVal.(bool); ok {
					tokenMounted = b
				}
			} else {
				// Fall back to SA-level value.
				saKey := r.GetNamespace() + "/" + saName
				if saVal, ok := saAutomountByNsName[saKey]; ok && saVal != nil {
					tokenMounted = *saVal
				} else {
					tokenMounted = true // Kubernetes default
				}
			}
		}

		out = append(out, ServiceAccountBinding{
			WorkloadRef:        ref,
			ServiceAccountName: saName,
			Namespace:          r.GetNamespace(),
			TokenMounted:       tokenMounted,
		})
	}
	return out
}
