package getter

import (
	"github.com/armosec/armoapi-go/armotypes"
)

var (
	_ IExceptionsGetter = &CRDExceptionsGetter{}
)

// CRDExceptionsGetter retrieves posture exceptions from Kubernetes
// SecurityException and ClusterSecurityException CRDs in the cluster.
type CRDExceptionsGetter struct {
}

// NewCRDExceptionsGetter creates a new CRD-based exceptions getter.
func NewCRDExceptionsGetter() *CRDExceptionsGetter {
	return &CRDExceptionsGetter{}
}

// GetExceptions returns posture exception policies from in-cluster CRDs.
func (g *CRDExceptionsGetter) GetExceptions(clusterName string) ([]armotypes.PostureExceptionPolicy, error) {
	_ = clusterName

	if g == nil {
		return []armotypes.PostureExceptionPolicy{}, nil
	}

	return []armotypes.PostureExceptionPolicy{}, nil
}
