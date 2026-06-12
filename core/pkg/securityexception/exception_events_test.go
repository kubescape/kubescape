package securityexception

import (
	"testing"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUnstructuredForCRD(t *testing.T) {
	ref := CRDReference{
		Kind:      "SecurityException",
		Name:      "se-a",
		Namespace: "team-a",
		UID:       "uid-1",
	}

	obj := UnstructuredForCRD(ref)

	// The Event's involvedObject.apiVersion must match the version the Helm chart
	// registers the CRD at, otherwise the reference dangles.
	assert.Equal(t, "kubescape.io/v1beta1", obj.GetAPIVersion())
	assert.Equal(t, "SecurityException", obj.GetKind())
	assert.Equal(t, "se-a", obj.GetName())
	assert.Equal(t, "team-a", obj.GetNamespace())
	assert.Equal(t, "uid-1", string(obj.GetUID()))
}

func TestUnstructuredForCRD_ClusterScoped(t *testing.T) {
	obj := UnstructuredForCRD(CRDReference{Kind: "ClusterSecurityException", Name: "cse-a"})

	assert.Equal(t, "kubescape.io/v1beta1", obj.GetAPIVersion())
	assert.Equal(t, "ClusterSecurityException", obj.GetKind())
	assert.Equal(t, "cse-a", obj.GetName())
	assert.Empty(t, obj.GetNamespace())
	assert.Empty(t, string(obj.GetUID()))
}

func TestCRDReferenceAttributesRoundTrip(t *testing.T) {
	ref := CRDReference{
		Kind:      "SecurityException",
		Name:      "se-a",
		Namespace: "team-a",
		UID:       "uid-1",
	}

	policy := armotypes.PostureExceptionPolicy{}
	policy.Attributes = CRDReferenceAttributes(ref)

	got, ok := CRDReferenceFromPolicy(policy)
	require.True(t, ok)
	assert.Equal(t, ref, got)
}

func TestCRDReferenceAttributesOmitsEmptyOptionalFields(t *testing.T) {
	attrs := CRDReferenceAttributes(CRDReference{Kind: "ClusterSecurityException", Name: "cse-a"})

	assert.Equal(t, "ClusterSecurityException", attrs[crdKindAttribute])
	assert.Equal(t, "cse-a", attrs[crdNameAttribute])
	assert.NotContains(t, attrs, crdNamespaceAttribute)
	assert.NotContains(t, attrs, crdUIDAttribute)
}

func TestCRDReferenceFromPolicyNotCRDBacked(t *testing.T) {
	withAttrs := func(attrs map[string]interface{}) armotypes.PostureExceptionPolicy {
		policy := armotypes.PostureExceptionPolicy{}
		policy.Attributes = attrs
		return policy
	}

	tests := []struct {
		name   string
		policy armotypes.PostureExceptionPolicy
	}{
		{name: "nil attributes", policy: armotypes.PostureExceptionPolicy{}},
		{name: "missing kind", policy: withAttrs(map[string]interface{}{crdNameAttribute: "se-a"})},
		{name: "missing name", policy: withAttrs(map[string]interface{}{crdKindAttribute: "SecurityException"})},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, ok := CRDReferenceFromPolicy(tc.policy)
			assert.False(t, ok)
		})
	}
}
