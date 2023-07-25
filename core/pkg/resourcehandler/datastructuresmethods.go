package resourcehandler

import (
	"fmt"

	"github.com/kubescape/kubescape/v2/core/cautils"
)

func (qr *QueryableResource) String() string {
	if qr.FieldSelectors == "" {
		return qr.GroupVersionResourceTriplet
	}
	return fmt.Sprintf("%s/%s", qr.GroupVersionResourceTriplet, qr.FieldSelectors)
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

	qr.FieldSelectors = CombineFieldSelectors(qr.FieldSelectors, fieldSelector)
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
