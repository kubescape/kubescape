package networkpolicy

import (
	"encoding/json"
	"fmt"
	"maps"
	"slices"

	"github.com/kubescape/k8s-interface/workloadinterface"
	networkingv1 "k8s.io/api/networking/v1"
)

// FromResources converts kubescape's generically-collected scan resources
// into the typed inputs NewIndex needs. Any object that is not a
// NetworkPolicy or Namespace is ignored. A NetworkPolicy or Namespace object
// that fails to decode into its typed shape is skipped, with its error
// appended to errs, rather than aborting the whole conversion over one bad
// object.
//
// Resources are visited in resource-ID order rather than map order, as in
// rbacgraph.FromResources: the order of the returned policies decides which
// policy a Decision or Exposure names when more than one applies, and map
// iteration order is randomized, so the same snapshot would otherwise name a
// different policy on different runs.
func FromResources(resources map[string]workloadinterface.IMetadata) (policies []*networkingv1.NetworkPolicy, namespaces []NamespaceInfo, errs []error) {
	for _, id := range slices.Sorted(maps.Keys(resources)) {
		resource := resources[id]
		if resource == nil {
			continue
		}
		switch resource.GetKind() {
		case "NetworkPolicy":
			p, err := decodeNetworkPolicy(resource.GetObject())
			if err != nil {
				errs = append(errs, fmt.Errorf("resource %s: %w", resource.GetID(), err))
				continue
			}
			policies = append(policies, p)
		case "Namespace":
			namespaces = append(namespaces, NamespaceInfo{
				Name:   resource.GetName(),
				Labels: resourceLabels(resource),
			})
		}
	}
	return policies, namespaces, errs
}

// decodeNetworkPolicy converts a NetworkPolicy's generic object map into its
// typed shape via a JSON round-trip, the same pattern the rest of this
// codebase uses to bridge kubescape's generic resource representation and a
// concrete Kubernetes API type.
func decodeNetworkPolicy(obj map[string]any) (*networkingv1.NetworkPolicy, error) {
	b, err := json.Marshal(obj)
	if err != nil {
		return nil, fmt.Errorf("marshal: %w", err)
	}
	var p networkingv1.NetworkPolicy
	if err := json.Unmarshal(b, &p); err != nil {
		return nil, fmt.Errorf("unmarshal: %w", err)
	}
	return &p, nil
}

// resourceLabels extracts a resource's labels. IMetadata does not carry
// labels itself; IBasicWorkload does.
func resourceLabels(resource workloadinterface.IMetadata) map[string]string {
	bw, ok := resource.(workloadinterface.IBasicWorkload)
	if !ok {
		return nil
	}
	return bw.GetLabels()
}

// EndpointFromResource builds an Endpoint from a scanned Pod-shaped
// resource, for use as a reachability query's source or destination.
func EndpointFromResource(resource workloadinterface.IMetadata) Endpoint {
	if resource == nil {
		return Endpoint{}
	}
	return Endpoint{
		Namespace:   resource.GetNamespace(),
		Name:        resource.GetName(),
		Labels:      resourceLabels(resource),
		HostNetwork: resourceHostNetwork(resource),
	}
}

// resourceHostNetwork reports whether a Pod-shaped resource sets
// spec.hostNetwork. IMetadata does not carry a pod spec; IWorkload does.
func resourceHostNetwork(resource workloadinterface.IMetadata) bool {
	w, ok := resource.(workloadinterface.IWorkload)
	if !ok {
		return false
	}
	podSpec, err := w.GetPodSpec()
	if err != nil || podSpec == nil {
		return false
	}
	return podSpec.HostNetwork
}
