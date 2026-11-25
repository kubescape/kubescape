package resourcehandler

import (
	"context"
	"errors"
	"testing"

	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	discoveryfake "k8s.io/client-go/discovery/fake"
	"k8s.io/client-go/dynamic/fake"
	k8stesting "k8s.io/client-go/testing"
)

func webhookConfigHandler(t *testing.T, listErr error, objects ...runtime.Object) *K8sResourceHandler {
	t.Helper()
	listKinds := map[schema.GroupVersionResource]string{
		{Group: "admissionregistration.k8s.io", Version: "v1", Resource: "validatingwebhookconfigurations"}: "ValidatingWebhookConfigurationList",
		{Group: "admissionregistration.k8s.io", Version: "v1", Resource: "mutatingwebhookconfigurations"}:   "MutatingWebhookConfigurationList",
	}
	dyn := fake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), listKinds, objects...)
	if listErr != nil {
		dyn.PrependReactor("list", "mutatingwebhookconfigurations", func(k8stesting.Action) (bool, runtime.Object, error) {
			return true, nil, listErr
		})
	}
	disc := &discoveryfake.FakeDiscovery{Fake: &k8stesting.Fake{}}
	disc.Resources = []*metav1.APIResourceList{{
		GroupVersion: "admissionregistration.k8s.io/v1",
		APIResources: []metav1.APIResource{{Name: "validatingwebhookconfigurations"}, {Name: "mutatingwebhookconfigurations"}},
	}}
	k8s := &k8sinterface.KubernetesApi{DynamicClient: dyn, DiscoveryClient: disc, Context: context.Background()}
	return &K8sResourceHandler{k8s: k8s}
}

func validatingConfig(name string) *unstructured.Unstructured {
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "admissionregistration.k8s.io/v1",
		"kind":       "ValidatingWebhookConfiguration",
		"metadata":   map[string]any{"name": name},
		"webhooks":   []any{map[string]any{"name": "w.example", "clientConfig": map[string]any{"url": "https://example.invalid"}}},
	}}
}

func TestCollectWebhookConfigurationsRecordsBothKindsOnSession(t *testing.T) {
	handler := webhookConfigHandler(t, nil, validatingConfig("cfg"))
	session := &cautils.OPASessionObj{}

	handler.collectWebhookConfigurations(context.Background(), session)

	require.NotNil(t, session.WebhookConfigurations)
	assert.Len(t, session.WebhookConfigurations.Validating, 1)
	assert.True(t, session.WebhookConfigurations.Complete())
}

func TestCollectWebhookConfigurationsNoneIsAvailableAndEmpty(t *testing.T) {
	handler := webhookConfigHandler(t, nil)
	session := &cautils.OPASessionObj{}

	handler.collectWebhookConfigurations(context.Background(), session)

	require.NotNil(t, session.WebhookConfigurations)
	assert.True(t, session.WebhookConfigurations.ValidatingSource.Available)
	assert.Empty(t, session.WebhookConfigurations.Validating)
}

func TestCollectWebhookConfigurationsFailureIsKeptNotEmpty(t *testing.T) {
	handler := webhookConfigHandler(t, errors.New("boom"), validatingConfig("cfg"))
	session := &cautils.OPASessionObj{}

	handler.collectWebhookConfigurations(context.Background(), session)

	require.NotNil(t, session.WebhookConfigurations)
	assert.False(t, session.WebhookConfigurations.MutatingSource.Available)
	require.Error(t, session.WebhookConfigurations.MutatingSource.Err)
	assert.Len(t, session.WebhookConfigurations.Validating, 1, "the readable kind is still collected")
	assert.False(t, session.WebhookConfigurations.Complete())
}

func TestCollectWebhookConfigurationsWithoutClientLeavesSessionUntouched(t *testing.T) {
	for name, handler := range map[string]*K8sResourceHandler{
		"nil api":           {},
		"no dynamic client": {k8s: &k8sinterface.KubernetesApi{}},
	} {
		t.Run(name, func(t *testing.T) {
			session := &cautils.OPASessionObj{}
			handler.collectWebhookConfigurations(context.Background(), session)
			assert.Nil(t, session.WebhookConfigurations, "unavailable must not become an empty collection")
		})
	}
}
