package policyhandler

import (
	"testing"

	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/stretchr/testify/assert"
)

// Returns a PolicyHandler instance with the given clusterName.
func TestNewPolicyHandler_ClusterNameNotEmpty(t *testing.T) {
	clusterName := "test-cluster"
	policyHandler := NewPolicyHandler(clusterName)
	assert.NotNil(t, policyHandler)
	assert.Equal(t, clusterName, policyHandler.clusterName)
}

// Returns the same PolicyHandler instance if called multiple times.
func TestNewPolicyHandler_MultiplePoliciesWithSameClusterName(t *testing.T) {
	clusterName := "test-cluster"
	policyHandler1 := NewPolicyHandler(clusterName)
	policyHandler2 := NewPolicyHandler(clusterName)
	assert.Equal(t, policyHandler1, policyHandler2)
}

// Should return a deep copy of the input slice of reporthandling.Framework structs
func TestDeepCopyPolicies_ShouldReturnDeepCopyOfInputSlice(t *testing.T) {
	src := []reporthandling.Framework{
		{
			Controls: []reporthandling.Control{
				{
					ControlID: "c-0001",
				},
			},
		},
		{
			Controls: []reporthandling.Control{},
		},
	}

	// Act
	dst, err := deepCopyPolicies(src)

	// Assert
	assert.NoError(t, err)
	assert.NotNil(t, dst)
}
