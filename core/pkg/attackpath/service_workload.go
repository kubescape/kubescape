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
    // Service's selector. Empty when the Service is selector-less/headless
    // or no collected workload matches.
    Backends []WorkloadRef
    // Headless is true when the Service has no selector at all (a headless
    // Service); no backend edge is emitted for it per the reliability bar.
    Headless bool
}

// ResolveServiceBackends matches every Service's spec.selector against
// pod-template labels in resources, visiting Services in namespace/name
// order for determinism.
// A selector-less Service is reported as Headless=true with no Backends.
// A Service whose selector matches nothing is reported with an empty
// Backends slice (not Headless — it has a selector, just nothing behind it).
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
        if r == nil {
            continue
        }
        if _, ok := WorkloadKindGVRs[r.GetKind()]; !ok {
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
            if a.Namespace < b.Namespace { return -1 }
            return 1
        }
        if a.Name < b.Name { return -1 }
        if a.Name > b.Name { return 1 }
        return 0
    })

    out := make([]ServiceBackend, 0, len(sorted))
    for _, svc := range sorted {
        if svc.Spec.Selector == nil || len(svc.Spec.Selector) == 0 {
            out = append(out, ServiceBackend{
                ServiceNamespace: svc.Namespace,
                ServiceName:      svc.Name,
                Headless:         true,
            })
            continue
        }
        sel := labels.SelectorFromSet(labels.Set(svc.Spec.Selector))
        sb := ServiceBackend{
            ServiceNamespace: svc.Namespace,
            ServiceName:      svc.Name,
        }
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
