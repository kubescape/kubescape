package resourcehandler

import (
	"strings"

	"github.com/kubescape/kubescape/v3/core/cautils"
)

type QueryableResources map[string]QueryableResource

// QueryableResource is a struct that holds a representation of a resource we would like to query (from the K8S API, or from other sources)
type QueryableResource struct {
	// <api group/api version/resource>
	GroupVersionResourceTriplet string
	// metadata.name==<resource name>, metadata.namespace==<resource namespace> etc.
	FieldSelectors string
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

func (qrm QueryableResources) Add(qr QueryableResource) {
	qrm[qr.String()] = qr
}
