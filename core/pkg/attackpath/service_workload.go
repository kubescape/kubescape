package attackpath

import (
	"maps"
	"slices"

	"github.com/kubescape/k8s-interface/workloadinterface"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
)

// ServiceBackend records which workload resources a Service's selector
// matches against the pod-template labels in the collected resource map.
type ServiceBackend struct {
	ServiceNamespace string
	ServiceName      string
	// Backends are the workloads whose pod-template labels match the
	// Service's selector. Empty when the Service is selector-less
	// or no collected workload matches.
	Backends []WorkloadRef
	// Headless is true when spec.clusterIP is None. A headless Service
	// with a selector can still have workload backends.
	Headless bool
	// Selectorless is true when the Service has no selector; no workload
	// backends can be inferred for it.
	Selectorless bool
}

// ResolveServiceBackends matches every Service's spec.selector against
// pod-template labels in resources, visiting Services in namespace/name
// order for determinism.
// A selector-less Service is reported as Selectorless=true with no Backends.
// A Service whose selector matches nothing is reported with an empty
// Backends slice. Headless records spec.clusterIP independently of selectors.
func ResolveServiceBackends(
	services []corev1.Service,
	resources map[string]workloadinterface.IMetadata,
) []ServiceBackend {
	// Pre-resolve pod-template labels for every known workload kind.
	type workloadLabels struct {
		ref    WorkloadRef
		labels labels.Set
	}
	var workloads []workloadLabels

	// Sort resource IDs for determinism.
	ids := slices.Sorted(maps.Keys(resources))
	for _, id := range ids {
		r := resources[id]
		if !isSupportedWorkloadResource(r) {
			continue
		}
		lbls := PodTemplateLabels(r.GetKind(), r.GetObject())
		if lbls == nil {
			continue // no pod-template labels: can't be selected
		}
		workloads = append(workloads, workloadLabels{
			ref:    WorkloadRef{Namespace: r.GetNamespace(), Kind: r.GetKind(), Name: r.GetName()},
			labels: labels.Set(lbls),
		})
	}

	// Match each Service's selector.
	// Services are already in the order exposure.FromResources produced them;
	// sort by namespace/name for determinism.
	sorted := make([]corev1.Service, len(services))
	copy(sorted, services)
	slices.SortFunc(sorted, func(a, b corev1.Service) int {
		if a.Namespace != b.Namespace {
			if a.Namespace < b.Namespace {
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

	out := make([]ServiceBackend, 0, len(sorted))
	for _, svc := range sorted {
		// ExternalName Services have no pod selector and route to an external
		// DNS name; Kubernetes ignores their selector entirely, so matching
		// them here would link the Service to the wrong local workload.
		if svc.Spec.Type == corev1.ServiceTypeExternalName {
			continue
		}
		sb := ServiceBackend{
			ServiceNamespace: svc.Namespace,
			ServiceName:      svc.Name,
			Headless:         svc.Spec.ClusterIP == corev1.ClusterIPNone,
			Selectorless:     len(svc.Spec.Selector) == 0,
		}
		if sb.Selectorless {
			out = append(out, sb)
			continue
		}
		sel := labels.SelectorFromSet(labels.Set(svc.Spec.Selector))
		for _, wl := range workloads {
			// A Service only selects pods in its own namespace.
			if wl.ref.Namespace != svc.Namespace {
				continue
			}
			if sel.Matches(wl.labels) {
				sb.Backends = append(sb.Backends, wl.ref)
			}
		}
		out = append(out, sb)
	}
	return out
}
