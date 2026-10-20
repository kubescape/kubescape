package resourcehandler

import (
	"strings"

	"github.com/kubescape/kubescape/v4/core/cautils"
)

type QueryableResources map[string]QueryableResource

// QueryableResource is a struct that holds a representation of a resource we would like to query (from the K8S API, or from other sources)
type QueryableResource struct {
	// <api group/api version/resource>
	GroupVersionResourceTriplet string
	// metadata.name==<resource name>, metadata.namespace==<resource namespace> etc.
	FieldSelectors string
	// Namespaced carries authoritative discovery scope when available. A nil
	// value preserves the existing k8s-interface scope lookup.
	Namespaced *bool
	// Kind is the Kind the API server serves this resource as, empty when the
	// resolver could not name it. It lets query planning honor the kind filters
	// before the LIST runs (see filterQueryableResourcesByKind).
	Kind string
	// RuleFiltered is true when a rule's match.fieldSelector narrows this
	// query, so its LIST returns only some of the resource's objects.
	RuleFiltered bool
}

func (qr *QueryableResource) String() string {
	if qr.FieldSelectors == "" {
		return qr.GroupVersionResourceTriplet
	}
	return strings.Join([]string{qr.GroupVersionResourceTriplet, qr.FieldSelectors}, "/")
}

func (qr *QueryableResource) Copy() QueryableResource {
	return QueryableResource{
		GroupVersionResourceTriplet: qr.GroupVersionResourceTriplet,
		FieldSelectors:              qr.FieldSelectors,
		Namespaced:                  qr.Namespaced,
		Kind:                        qr.Kind,
		RuleFiltered:                qr.RuleFiltered,
	}
}

func (qr *QueryableResource) AddFieldSelector(fieldSelector string) {
	if fieldSelector == "" {
		return
	}

	if qr.FieldSelectors == "" {
		qr.FieldSelectors = fieldSelector
		return
	}

	qr.FieldSelectors = combineFieldSelectors(qr.FieldSelectors, fieldSelector)
}

func (qrm QueryableResources) ToK8sResourceMap() cautils.K8SResources {
	resources := make(cautils.K8SResources)
	for _, qr := range qrm {
		resources[qr.GroupVersionResourceTriplet] = nil
	}
	return resources
}

// ListedGVRs maps each queried <api group/api version/resource> to whether at
// least one of its queries carries no rule field selector, so that its LIST
// returns every object in the scan scope.
func (qrm QueryableResources) ListedGVRs() map[string]bool {
	listed := make(map[string]bool, len(qrm))
	for _, qr := range qrm {
		listed[qr.GroupVersionResourceTriplet] = listed[qr.GroupVersionResourceTriplet] || !qr.RuleFiltered
	}
	return listed
}

func (qrm QueryableResources) Add(qr QueryableResource) {
	qrm[qr.String()] = qr
}
