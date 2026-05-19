package getter

import (
	"fmt"

	"github.com/armosec/armoapi-go/armotypes"
)

var (
	_ IExceptionsGetter = &CRDExceptionsGetter{}
)

// CRDExceptionsGetter will retrieve posture exceptions from Kubernetes
// SecurityException and ClusterSecurityException CRDs in the cluster.
//
// Currently a structural skeleton that always returns an empty slice.
// The full implementation will use a Kubernetes dynamic client to list
// and convert CRD instances into PostureExceptionPolicy objects when the
// SecurityException CRD has been defined (kubescape/kubescape#1982).
type CRDExceptionsGetter struct {
	// client holds the Kubernetes dynamic client for querying
	// SecurityException / ClusterSecurityException CRDs.
	//
	// TODO(kubescape/kubescape#1982): populate with a live dynamic.Interface
	// when the CRD has been defined in the Helm chart.
}

// NewCRDExceptionsGetter creates a new CRD-based exceptions getter.
func NewCRDExceptionsGetter() *CRDExceptionsGetter {
	return &CRDExceptionsGetter{}
}

// GetExceptions returns posture exception policies from in-cluster CRDs.
//
// Currently returns an empty slice because the SecurityException CRD has not
// yet been registered. Once the CRD is available, this method will:
//  1. List SecurityException resources (namespaced) and map them to
//     armotypes.PostureExceptionPolicy.
//  2. List ClusterSecurityException resources (cluster-scoped) and map them
//     to armotypes.PostureExceptionPolicy.
//  3. Evaluate expiresAt at scan time and skip expired entries.
//  4. Emit Kubernetes Events on matched SecurityException resources.
//
// TODO(kubescape/kubescape#1982): implement CRD listing and conversion
func (g *CRDExceptionsGetter) GetExceptions(clusterName string) ([]armotypes.PostureExceptionPolicy, error) {
	// Placeholder: returns an empty slice. The CRD-powered implementation
	// will use a dynamic client to list SecurityException and
	// ClusterSecurityException resources from the cluster.
	_ = clusterName // reserved for future use (e.g., filtering by cluster label)

	if g == nil {
		return nil, fmt.Errorf("CRDExceptionsGetter is nil")
	}

	return []armotypes.PostureExceptionPolicy{}, nil
}
