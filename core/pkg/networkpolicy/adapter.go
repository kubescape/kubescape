package networkpolicy

import (
	"encoding/json"
	"fmt"

	"github.com/kubescape/k8s-interface/workloadinterface"
	networkingv1 "k8s.io/api/networking/v1"
)

// FromResources converts kubescape's generically-collected scan resources
// into the typed inputs NewIndex needs. Any object that is not a
// NetworkPolicy or Namespace is ignored. A NetworkPolicy or Namespace object
// that fails to decode into its typed shape is skipped, with its error
// appended to errs, rather than aborting the whole conversion over one bad
// object.
func FromResources(resources map[string]workloadinterface.IMetadata) (policies []*networkingv1.NetworkPolicy, namespaces []NamespaceInfo, errs []error) {
	for _, resource := range resources {
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
		Namespace: resource.GetNamespace(),
		Name:      resource.GetName(),
		Labels:    resourceLabels(resource),
	}
}
