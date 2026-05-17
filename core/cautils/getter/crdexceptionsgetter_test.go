package getter

import (
	"testing"
	"time"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/dynamic/fake"
)

// mockFallbackGetter is a test double for IExceptionsGetter
type mockFallbackGetter struct {
	exceptions []armotypes.PostureExceptionPolicy
	err        error
}

func (m *mockFallbackGetter) GetExceptions(_ string) ([]armotypes.PostureExceptionPolicy, error) {
	return m.exceptions, m.err
}

func makeSecurityException(name, namespace, controlID, action, expiresAt string) *unstructured.Unstructured {
	obj := &unstructured.Unstructured{}
	obj.SetGroupVersionKind(securityExceptionGVK())
	obj.SetName(name)
	obj.SetNamespace(namespace)

	spec := map[string]interface{}{
		"reason": "accepted-risk",
		"posture": []interface{}{
			map[string]interface{}{
				"controlID": controlID,
				"action":    action,
			},
		},
		"match": map[string]interface{}{
			"resources": []interface{}{
				map[string]interface{}{
					"kind": "Deployment",
					"name": "nginx",
				},
			},
		},
	}
	if expiresAt != "" {
		spec["expiresAt"] = expiresAt
	}
	obj.Object["spec"] = spec
	return obj
}

func securityExceptionGVK() metav1.GroupVersionKind {
	return metav1.GroupVersionKind{
		Group:   "kubescape.io",
		Version: "v1beta1",
		Kind:    "SecurityException",
	}
}

func TestGetExceptions_CRDOnly(t *testing.T) {
	// ARRANGE
	scheme := runtime.NewScheme()
	se := makeSecurityException("test-se", "default", "C-0016", "ignore", "")

	dynamicClient := fake.NewSimpleDynamicClient(scheme, se)

	getter := NewCRDExceptionsGetter(dynamicClient, nil)

	// ACT
	policies, err := getter.GetExceptions("test-cluster")

	// ASSERT
	require.NoError(t, err)
	assert.Len(t, policies, 1)
	assert.Equal(t, "C-0016", policies[0].PostureControlIDs[0].ControlID)
	assert.Equal(t, armotypes.Ignore, policies[0].PostureControlIDs[0].Action)
}

func TestGetExceptions_MergesWithFallback(t *testing.T) {
	// ARRANGE
	scheme := runtime.NewScheme()
	se := makeSecurityException("test-se", "default", "C-0016", "ignore", "")
	dynamicClient := fake.NewSimpleDynamicClient(scheme, se)

	fallback := &mockFallbackGetter{
		exceptions: []armotypes.PostureExceptionPolicy{
			{
				PortalBase: armotypes.PortalBase{Name: "cloud-exception"},
				PostureControlIDs: []armotypes.PostureControlID{
					{ControlID: "C-0020", Action: armotypes.AlertOnly},
				},
			},
		},
	}

	getter := NewCRDExceptionsGetter(dynamicClient, fallback)

	// ACT
	policies, err := getter.GetExceptions("test-cluster")

	// ASSERT
	require.NoError(t, err)
	assert.Len(t, policies, 2)
	// fallback first
	assert.Equal(t, "cloud-exception", policies[0].Name)
	// CRD second
	assert.Equal(t, "C-0016", policies[1].PostureControlIDs[0].ControlID)
}

func TestGetExceptions_SkipsExpired(t *testing.T) {
	// ARRANGE
	scheme := runtime.NewScheme()
	past := time.Now().Add(-24 * time.Hour).UTC().Format(time.RFC3339)
	se := makeSecurityException("expired-se", "default", "C-0016", "ignore", past)
	dynamicClient := fake.NewSimpleDynamicClient(scheme, se)

	getter := NewCRDExceptionsGetter(dynamicClient, nil)

	// ACT
	policies, err := getter.GetExceptions("test-cluster")

	// ASSERT
	require.NoError(t, err)
	assert.Len(t, policies, 0, "expired exception should be filtered out")
}

func TestGetExceptions_NilDynamicClient_UsesFallbackOnly(t *testing.T) {
	// ARRANGE
	fallback := &mockFallbackGetter{
		exceptions: []armotypes.PostureExceptionPolicy{
			{PortalBase: armotypes.PortalBase{Name: "fallback-only"}},
		},
	}
	getter := NewCRDExceptionsGetter(nil, fallback)

	// ACT
	policies, err := getter.GetExceptions("test-cluster")

	// ASSERT
	require.NoError(t, err)
	assert.Len(t, policies, 1)
	assert.Equal(t, "fallback-only", policies[0].Name)
}

func TestConvertToPolicyException_MapsFields(t *testing.T) {
	// ARRANGE
	obj := map[string]interface{}{
		"metadata": map[string]interface{}{
			"name":      "my-exception",
			"namespace": "production",
		},
		"spec": map[string]interface{}{
			"reason":    "false-positive",
			"expiresAt": "2099-01-01T00:00:00Z",
			"posture": []interface{}{
				map[string]interface{}{
					"controlID": "C-0016",
					"action":    "ignore",
				},
			},
			"match": map[string]interface{}{
				"resources": []interface{}{
					map[string]interface{}{
						"kind": "Deployment",
						"name": "nginx",
					},
				},
				"objectSelector": map[string]interface{}{
					"matchLabels": map[string]interface{}{
						"app": "nginx",
					},
				},
			},
		},
	}

	// ACT
	policy, err := convertToPolicyException(obj)

	// ASSERT
	require.NoError(t, err)
	assert.Equal(t, "false-positive", policy.Reason)
	assert.Equal(t, "C-0016", policy.PostureControlIDs[0].ControlID)
	assert.Equal(t, armotypes.Ignore, policy.PostureControlIDs[0].Action)
	assert.Equal(t, "Deployment", policy.Resources[0].Attributes["kind"])
	assert.Equal(t, "nginx", policy.Resources[0].Attributes["label.app"])
}

func TestIsExpired(t *testing.T) {
	past := time.Now().Add(-1 * time.Hour).UTC().Format(time.RFC3339)
	future := time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339)

	assert.True(t, isExpired(&armotypes.PostureExceptionPolicy{ExpiresAt: past}))
	assert.False(t, isExpired(&armotypes.PostureExceptionPolicy{ExpiresAt: future}))
	assert.False(t, isExpired(&armotypes.PostureExceptionPolicy{ExpiresAt: ""}))
}
