package getter

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic/fake"
	crfake "sigs.k8s.io/controller-runtime/pkg/client/fake"
)

// TestCRDExceptionsGetter_ZeroMatchNamespaceSelectorMustNotWiden pins the bug:
// a ClusterSecurityException whose namespaceSelector matches no namespace in
// the cluster must not degrade into a scopeless (Resources == nil) exception
// policy, because Kubescape's own exception matching treats an empty
// Resources list as "matches every cluster" (see
// opaprocessor.hasExplicitControlException), turning a narrowly-scoped
// exception into a silent, cluster-wide one. The CRD is dropped (with a
// logged warning, like any other malformed CRD) instead of being widened.
func TestCRDExceptionsGetter_ZeroMatchNamespaceSelectorMustNotWiden(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	// No namespace in the cluster carries the label the selector asks for.
	k8sClient := crfake.NewClientBuilder().WithScheme(scheme).WithObjects(
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "default"}},
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "prod", Labels: map[string]string{"env": "prod"}}},
	).Build()

	listKinds := map[schema.GroupVersionResource]string{
		securityExceptionGVR:        "SecurityExceptionList",
		clusterSecurityExceptionGVR: "ClusterSecurityExceptionList",
	}
	dynamicClient := fake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), listKinds,
		&unstructured.Unstructured{
			Object: map[string]any{
				"apiVersion": "kubescape.io/v1beta1",
				"kind":       "ClusterSecurityException",
				"metadata":   map[string]any{"name": "cse-typo", "uid": "uid-1"},
				"spec": map[string]any{
					"match": map[string]any{
						"namespaceSelector": map[string]any{
							"matchLabels": map[string]any{"env": "staging-typo"},
						},
					},
					"posture": []any{
						map[string]any{"controlID": "C-0003", "action": "alert_only"},
					},
				},
			},
		},
	)

	g := &CRDExceptionsGetter{client: dynamicClient, k8sClient: k8sClient}
	exceptions, err := g.GetExceptions(context.TODO(), "cluster-a")
	require.NoError(t, err)

	// A selector that matched nothing must not produce an exception that
	// downstream treats as matching everything.
	for _, exception := range exceptions {
		require.NotEmpty(t, exception.Resources,
			"a namespaceSelector that matched zero namespaces must not yield a scopeless (cluster-wide) exception policy")
	}
	require.Empty(t, exceptions, "a zero-match namespaceSelector should drop the CRD, not silently widen it")
}
