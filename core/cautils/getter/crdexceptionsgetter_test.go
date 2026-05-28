package getter

import (
	"testing"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/armosec/armoapi-go/identifiers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic/fake"
	crfake "sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestCRDExceptionsGetter_GetExceptions(t *testing.T) {
	scheme := runtime.NewScheme()
	client := fake.NewSimpleDynamicClient(scheme,
		&unstructured.Unstructured{
			Object: map[string]any{
				"apiVersion": "kubescape.io/v1",
				"kind":       "SecurityException",
				"metadata": map[string]any{
					"name":      "se-a",
					"namespace": "team-a",
					"uid":       "uid-se-a",
				},
				"spec": map[string]any{
					"reason": "maintenance",
					"posture": []any{
						map[string]any{"controlID": "C-0001", "action": "ignore"},
					},
				},
			},
		},
		&unstructured.Unstructured{
			Object: map[string]any{
				"apiVersion": "kubescape.io/v1",
				"kind":       "ClusterSecurityException",
				"metadata": map[string]any{
					"name": "cse-a",
					"uid":  "uid-cse-a",
				},
				"spec": map[string]any{
					"posture": []any{
						map[string]any{"controlID": "C-0002", "action": "alert_only"},
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

func TestCRDExceptionsGetter_GetExceptionsResolvesClusterNamespaceSelector(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	k8sClient := crfake.NewClientBuilder().WithScheme(scheme).WithObjects(
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "staging", Labels: map[string]string{"env": "staging"}}},
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "prod", Labels: map[string]string{"env": "prod"}}},
	).Build()

	listKinds := map[schema.GroupVersionResource]string{
		securityExceptionGVR:        "SecurityExceptionList",
		clusterSecurityExceptionGVR: "ClusterSecurityExceptionList",
	}
	dynamicClient := fake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), listKinds,
		&unstructured.Unstructured{
			Object: map[string]any{
				"apiVersion": "kubescape.io/v1",
				"kind":       "ClusterSecurityException",
				"metadata": map[string]any{
					"name": "cse-staging",
					"uid":  "uid-cse-staging",
				},
				"spec": map[string]any{
					"match": map[string]any{
						"namespaceSelector": map[string]any{
							"matchLabels": map[string]any{"env": "staging"},
						},
					},
					"posture": []any{
						map[string]any{"controlID": "C-0003", "action": "alert_only"},
					},
				},
			},
		},
	)

	getter := &CRDExceptionsGetter{client: dynamicClient, k8sClient: k8sClient}
	exceptions, err := getter.GetExceptions("cluster-a")
	require.NoError(t, err)
	require.Len(t, exceptions, 1)
	require.Len(t, exceptions[0].Resources, 1)
	assert.Equal(t, "staging", exceptions[0].Resources[0].Attributes[identifiers.AttributeNamespace])
	assert.Equal(t, "ClusterSecurityException", exceptions[0].Attributes["securityExceptionKind"])
}

func TestConvertCRDObjectToPosturePolicies_DefaultScope(t *testing.T) {
	obj := &unstructured.Unstructured{}
	obj.SetGroupVersionKind(schema.GroupVersionKind{Group: "kubescape.io", Version: "v1", Kind: "ClusterSecurityException"})
	obj.SetName("cse-empty")
	obj.SetUID("uid-cse")
	obj.Object["spec"] = map[string]any{
		"posture": []any{
			map[string]any{"controlID": "C-0099"},
		},
	}

	policies, err := convertCRDObjectToPosturePolicies(obj, "ClusterSecurityException", nil)
	require.NoError(t, err)
	require.Len(t, policies, 1)
	assert.Equal(t, "*", policies[0].Resources[0].Attributes[identifiers.AttributeKind])
}

func TestConvertCRDObjectToPosturePolicies_ObjectSelectorIsRejected(t *testing.T) {
	obj := &unstructured.Unstructured{}
	obj.SetGroupVersionKind(schema.GroupVersionKind{Group: "kubescape.io", Version: "v1", Kind: "SecurityException"})
	obj.SetName("se-selector")
	obj.SetNamespace("team-a")
	obj.Object["spec"] = map[string]any{
		"match": map[string]any{
			"objectSelector": map[string]any{
				"matchLabels": map[string]any{"app": "nginx"},
			},
		},
		"posture": []any{
			map[string]any{"controlID": "C-0100", "action": "ignore"},
		},
	}

	policies, err := convertCRDObjectToPosturePolicies(obj, "SecurityException", nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "spec.match.objectSelector is not supported")
	assert.Nil(t, policies)
}

func TestBuildResourceDesignators_NamespaceSelector(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))

	k8sClient := crfake.NewClientBuilder().WithScheme(scheme).WithObjects(
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "staging", Labels: map[string]string{"env": "staging"}}},
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "staging-2", Labels: map[string]string{"env": "staging"}}},
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "prod", Labels: map[string]string{"env": "prod"}}},
	).Build()

	tests := []struct {
		name      string
		kind      string
		namespace string
		selector  map[string]any
		resources []map[string]any
		want      []map[string]string
	}{
		{
			name: "namespaceSelector matches one namespace",
			kind: "ClusterSecurityException",
			selector: map[string]any{
				"matchLabels": map[string]any{"env": "prod"},
			},
			want: []map[string]string{{identifiers.AttributeNamespace: "prod"}},
		},
		{
			name: "namespaceSelector matches multiple namespaces",
			kind: "ClusterSecurityException",
			selector: map[string]any{
				"matchLabels": map[string]any{"env": "staging"},
			},
			want: []map[string]string{
				{identifiers.AttributeNamespace: "staging"},
				{identifiers.AttributeNamespace: "staging-2"},
			},
		},
		{
			name: "namespaceSelector with resources combines scope",
			kind: "ClusterSecurityException",
			selector: map[string]any{
				"matchLabels": map[string]any{"env": "staging"},
			},
			resources: []map[string]any{
				{
					"kind":     "Deployment",
					"name":     "frontend",
					"apiGroup": "apps",
				},
			},
			want: []map[string]string{
				{
					identifiers.AttributeNamespace: "staging",
					identifiers.AttributeKind:      "Deployment",
					identifiers.AttributeName:      "frontend",
					identifiers.AttributeApiGroup:  "apps",
				},
				{
					identifiers.AttributeNamespace: "staging-2",
					identifiers.AttributeKind:      "Deployment",
					identifiers.AttributeName:      "frontend",
					identifiers.AttributeApiGroup:  "apps",
				},
			},
		},
		{
			name: "namespaceSelector matches no namespaces",
			kind: "ClusterSecurityException",
			selector: map[string]any{
				"matchLabels": map[string]any{"env": "dev"},
			},
			want: []map[string]string{},
		},
		{
			name: "namespaceSelector matches no namespaces with resources",
			kind: "ClusterSecurityException",
			selector: map[string]any{
				"matchLabels": map[string]any{"env": "dev"},
			},
			resources: []map[string]any{
				{
					"kind":     "Deployment",
					"name":     "frontend",
					"apiGroup": "apps",
				},
			},
			want: []map[string]string{},
		},
		{
			name:     "empty namespaceSelector matches all namespaces",
			kind:     "ClusterSecurityException",
			selector: map[string]any{},
			want: []map[string]string{
				{identifiers.AttributeNamespace: "prod"},
				{identifiers.AttributeNamespace: "staging"},
				{identifiers.AttributeNamespace: "staging-2"},
			},
		},
		{
			name: "nil namespaceSelector skips resolution",
			kind: "ClusterSecurityException",
			want: []map[string]string{{identifiers.AttributeKind: "*"}},
		},
		{
			name:      "namespaceSelector on namespaced SecurityException is ignored",
			kind:      "SecurityException",
			namespace: "team-a",
			selector: map[string]any{
				"matchLabels": map[string]any{"env": "staging"},
			},
			want: []map[string]string{{identifiers.AttributeNamespace: "team-a"}},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			match := map[string]any{}
			if tc.selector != nil {
				match["namespaceSelector"] = tc.selector
			}
			if len(tc.resources) > 0 {
				resources := make([]any, 0, len(tc.resources))
				for _, res := range tc.resources {
					resources = append(resources, res)
				}
				match["resources"] = resources
			}
			obj := &unstructured.Unstructured{Object: map[string]any{
				"apiVersion": "kubescape.io/v1",
				"kind":       tc.kind,
				"metadata": map[string]any{
					"name":      "exception-a",
					"namespace": tc.namespace,
				},
				"spec": map[string]any{
					"match": match,
					"posture": []any{
						map[string]any{"controlID": "C-0001", "action": "alert_only"},
					},
				},
			}}

			got, err := buildResourceDesignators(obj, tc.kind, k8sClient)
			require.NoError(t, err)
			assert.ElementsMatch(t, tc.want, got)
		})
	}
}
