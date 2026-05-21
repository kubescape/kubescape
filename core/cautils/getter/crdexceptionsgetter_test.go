package getter

import (
	"testing"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/armosec/armoapi-go/identifiers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic/fake"
)

func TestCRDExceptionsGetter_GetExceptions(t *testing.T) {
	scheme := runtime.NewScheme()
	client := fake.NewSimpleDynamicClient(scheme,
		&unstructured.Unstructured{
			Object: map[string]interface{}{
				"apiVersion": "kubescape.io/v1",
				"kind":       "SecurityException",
				"metadata": map[string]interface{}{
					"name":      "se-a",
					"namespace": "team-a",
					"uid":       "uid-se-a",
				},
				"spec": map[string]interface{}{
					"reason": "maintenance",
					"posture": []interface{}{
						map[string]interface{}{"controlID": "C-0001", "action": "ignore"},
					},
				},
			},
		},
		&unstructured.Unstructured{
			Object: map[string]interface{}{
				"apiVersion": "kubescape.io/v1",
				"kind":       "ClusterSecurityException",
				"metadata": map[string]interface{}{
					"name": "cse-a",
					"uid":  "uid-cse-a",
				},
				"spec": map[string]interface{}{
					"posture": []interface{}{
						map[string]interface{}{"controlID": "C-0002", "action": "alert_only"},
					},
				},
			},
		},
	)

	getter := &CRDExceptionsGetter{client: client}
	exceptions, err := getter.GetExceptions("cluster-a")
	require.NoError(t, err)
	require.Len(t, exceptions, 2)

	assert.Equal(t, string(armotypes.PostureExceptionPolicyType), exceptions[0].PolicyType)
	assert.Equal(t, "C-0001", exceptions[0].PosturePolicies[0].ControlID)
	assert.True(t, exceptions[0].IsDisable())
	assert.Equal(t, "team-a", exceptions[0].Resources[0].Attributes[identifiers.AttributeNamespace])
	assert.Equal(t, "SecurityException", exceptions[0].Attributes["securityExceptionKind"])
	assert.Equal(t, "se-a", exceptions[0].Attributes["securityExceptionName"])
	assert.Equal(t, "team-a", exceptions[0].Attributes["securityExceptionNamespace"])

	assert.Equal(t, "C-0002", exceptions[1].PosturePolicies[0].ControlID)
	assert.True(t, exceptions[1].IsAlertOnly())
	assert.Equal(t, "ClusterSecurityException", exceptions[1].Attributes["securityExceptionKind"])
	assert.Equal(t, "cse-a", exceptions[1].Attributes["securityExceptionName"])
}

func TestCRDExceptionsGetter_NilClient(t *testing.T) {
	getter := &CRDExceptionsGetter{}
	exceptions, err := getter.GetExceptions("cluster-a")
	require.NoError(t, err)
	assert.Empty(t, exceptions)
}

func TestConvertCRDObjectToPosturePolicies_DefaultScope(t *testing.T) {
	obj := &unstructured.Unstructured{}
	obj.SetGroupVersionKind(schema.GroupVersionKind{Group: "kubescape.io", Version: "v1", Kind: "ClusterSecurityException"})
	obj.SetName("cse-empty")
	obj.SetUID("uid-cse")
	obj.Object["spec"] = map[string]interface{}{
		"posture": []interface{}{
			map[string]interface{}{"controlID": "C-0099"},
		},
	}

	policies, err := convertCRDObjectToPosturePolicies(obj, "ClusterSecurityException")
	require.NoError(t, err)
	require.Len(t, policies, 1)
	assert.Equal(t, "*", policies[0].Resources[0].Attributes[identifiers.AttributeKind])
}

func TestConvertCRDObjectToPosturePolicies_ObjectSelectorIsRejected(t *testing.T) {
	obj := &unstructured.Unstructured{}
	obj.SetGroupVersionKind(schema.GroupVersionKind{Group: "kubescape.io", Version: "v1", Kind: "SecurityException"})
	obj.SetName("se-selector")
	obj.SetNamespace("team-a")
	obj.Object["spec"] = map[string]interface{}{
		"match": map[string]interface{}{
			"objectSelector": map[string]interface{}{
				"matchLabels": map[string]interface{}{"app": "nginx"},
			},
		},
		"posture": []interface{}{
			map[string]interface{}{"controlID": "C-0100", "action": "ignore"},
		},
	}

	policies, err := convertCRDObjectToPosturePolicies(obj, "SecurityException")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "spec.match.objectSelector is not supported")
	assert.Nil(t, policies)
}
