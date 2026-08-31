package opaprocessor

import (
	"context"
	"testing"

	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestProcessRulesListener_SurfacesUnexaminedKinds pins that ScanCoverage
// carries through whatever the resource collector recorded on
// sessionObj.UnexaminedKinds - the same pass-through BuildScanCoverage already
// does for VacuousFrameworks.
func TestProcessRulesListener_SurfacesUnexaminedKinds(t *testing.T) {
	policies := parityPolicies(false)
	opap := newParityProcessor(policies)
	opap.UnexaminedKinds = []cautils.UnexaminedKind{
		{GroupVersionResource: "gateway.networking.k8s.io/v1/httproutes", Kind: "HTTPRoute"},
	}

	require.NoError(t, opap.ProcessRulesListener(context.Background(), nil))

	assert.Equal(t, opap.UnexaminedKinds, opap.ScanCoverage.UnexaminedKinds)
}
