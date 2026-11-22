package webhookcoverage

import (
	"context"
	"errors"
	"testing"

	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	discoveryfake "k8s.io/client-go/discovery/fake"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	k8stesting "k8s.io/client-go/testing"
)

var (
	validatingGVR = schema.GroupVersionResource{Group: admissionGroup, Version: admissionVersion, Resource: validatingListing}
	mutatingGVR   = schema.GroupVersionResource{Group: admissionGroup, Version: admissionVersion, Resource: mutatingListing}
)

func configObject(kind, name string, webhooks ...any) *unstructured.Unstructured {
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": admissionGroup + "/" + admissionVersion,
		"kind":       kind,
		"metadata":   map[string]any{"name": name},
		"webhooks":   webhooks,
	}}
}

func webhookObject(name string) map[string]any {
	return map[string]any{"name": name, "clientConfig": map[string]any{"url": "https://example.invalid"}}
}

func fakeClient(objects ...runtime.Object) *dynamicfake.FakeDynamicClient {
	return dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), map[schema.GroupVersionResource]string{
		validatingGVR: "ValidatingWebhookConfigurationList",
		mutatingGVR:   "MutatingWebhookConfigurationList",
	}, objects...)
}

func servedDiscovery() *discoveryfake.FakeDiscovery {
	d := &discoveryfake.FakeDiscovery{Fake: &k8stesting.Fake{}}
	d.Resources = []*metav1.APIResourceList{{
		GroupVersion: admissionGroup + "/" + admissionVersion,
		APIResources: []metav1.APIResource{{Name: validatingListing}, {Name: mutatingListing}},
	}}
	return d
}

func api(client *dynamicfake.FakeDynamicClient) *k8sinterface.KubernetesApi {
	return &k8sinterface.KubernetesApi{DynamicClient: client, DiscoveryClient: servedDiscovery()}
}

func failList(client *dynamicfake.FakeDynamicClient, resource string, err error) {
	client.PrependReactor("list", resource, func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, err
	})
}

func TestCollect_ReadsBothKindsSortedByName(t *testing.T) {
	client := fakeClient(
		configObject("ValidatingWebhookConfiguration", "b-val", webhookObject("w")),
		configObject("ValidatingWebhookConfiguration", "a-val", webhookObject("w")),
		configObject("MutatingWebhookConfiguration", "m", webhookObject("w1"), webhookObject("w2")),
	)

	c, err := Collect(context.Background(), api(client))

	require.NoError(t, err)
	require.Len(t, c.Validating, 2)
	assert.Equal(t, "a-val", c.Validating[0].Name)
	assert.Equal(t, "b-val", c.Validating[1].Name)
	require.Len(t, c.Mutating, 1)
	assert.Len(t, c.Mutating[0].Webhooks, 2, "webhook identity inside the configuration is preserved")
	assert.True(t, c.Complete())
}

func TestCollect_EmptyListsAreAvailableNotFailed(t *testing.T) {
	c, err := Collect(context.Background(), api(fakeClient()))

	require.NoError(t, err)
	assert.True(t, c.ValidatingSource.Available)
	assert.True(t, c.MutatingSource.Available)
	assert.NoError(t, c.ValidatingSource.Err)
	assert.Empty(t, c.Validating)
	assert.True(t, c.Complete(), "a cluster with no webhooks is fully collected")
}

func TestCollect_FailureIsNotAnEmptyList(t *testing.T) {
	tests := []struct {
		name string
		err  error
		is   error
	}{
		{"forbidden", apierrors.NewForbidden(validatingGVR.GroupResource(), "", errors.New("no")), ErrForbidden},
		{"not found", apierrors.NewNotFound(validatingGVR.GroupResource(), ""), ErrUnsupported},
		{"other", errors.New("boom"), nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := fakeClient(configObject("MutatingWebhookConfiguration", "m", webhookObject("w")))
			failList(client, validatingListing, tt.err)

			c, err := Collect(context.Background(), api(client))

			require.NoError(t, err)
			assert.False(t, c.ValidatingSource.Available)
			require.Error(t, c.ValidatingSource.Err)
			if tt.is != nil {
				assert.ErrorIs(t, c.ValidatingSource.Err, tt.is)
			}
			assert.False(t, c.Complete(), "a failed list must not pass for complete collection")
			// The other kind is still collected.
			assert.True(t, c.MutatingSource.Available)
			require.Len(t, c.Mutating, 1)
		})
	}
}

func TestCollect_UndecodableConfigurationIsReportedNotDropped(t *testing.T) {
	bad := configObject("ValidatingWebhookConfiguration", "bad")
	bad.Object["webhooks"] = "not a list"
	client := fakeClient(bad, configObject("ValidatingWebhookConfiguration", "good", webhookObject("w")))

	c, err := Collect(context.Background(), api(client))

	require.NoError(t, err)
	require.Len(t, c.Validating, 1)
	assert.Equal(t, "good", c.Validating[0].Name)
	require.Len(t, c.ValidatingSource.DecodeErrs, 1)
	assert.Contains(t, c.ValidatingSource.DecodeErrs[0].Error(), "bad")
	assert.True(t, c.ValidatingSource.Available)
	assert.False(t, c.ValidatingSource.Complete())
	assert.False(t, c.Complete())
}

func TestCollect_DropsRepeatedNames(t *testing.T) {
	client := fakeClient()
	client.PrependReactor("list", validatingListing, func(k8stesting.Action) (bool, runtime.Object, error) {
		list := &unstructured.UnstructuredList{}
		list.SetAPIVersion(admissionGroup + "/" + admissionVersion)
		list.SetKind("ValidatingWebhookConfigurationList")
		list.Items = []unstructured.Unstructured{
			*configObject("ValidatingWebhookConfiguration", "dup", webhookObject("w")),
			*configObject("ValidatingWebhookConfiguration", "dup", webhookObject("w")),
		}
		return true, list, nil
	})

	c, err := Collect(context.Background(), api(client))

	require.NoError(t, err)
	assert.Len(t, c.Validating, 1)
}

func TestCollect_RequiresDynamicClient(t *testing.T) {
	c, err := Collect(context.Background(), nil)
	assert.Error(t, err)
	assert.Nil(t, c)

	c, err = Collect(context.Background(), &k8sinterface.KubernetesApi{})
	assert.Error(t, err)
	assert.Nil(t, c)
	assert.False(t, c.Complete(), "a nil collection is never complete")

	c, err = Collect(context.Background(), &k8sinterface.KubernetesApi{DynamicClient: fakeClient()})
	assert.ErrorIs(t, err, ErrDiscoveryRequired, "without discovery the API cannot be confirmed served")
	assert.Nil(t, c)
}

func TestCollect_UnservedAPIIsUnsupportedWithoutListing(t *testing.T) {
	client := fakeClient()
	listed := false
	client.PrependReactor("list", "*", func(k8stesting.Action) (bool, runtime.Object, error) {
		listed = true
		return false, nil, nil
	})
	k8s := &k8sinterface.KubernetesApi{DynamicClient: client, DiscoveryClient: &discoveryfake.FakeDiscovery{Fake: &k8stesting.Fake{}}}

	c, err := Collect(context.Background(), k8s)

	require.NoError(t, err)
	assert.ErrorIs(t, c.ValidatingSource.Err, ErrUnsupported)
	assert.ErrorIs(t, c.MutatingSource.Err, ErrUnsupported)
	assert.False(t, listed)
	assert.False(t, c.Complete())
}

func TestCollect_OnlyServedKindIsListed(t *testing.T) {
	d := servedDiscovery()
	d.Resources[0].APIResources = d.Resources[0].APIResources[:1] // validating only
	client := fakeClient(configObject("ValidatingWebhookConfiguration", "v", webhookObject("w")))

	c, err := Collect(context.Background(), &k8sinterface.KubernetesApi{DynamicClient: client, DiscoveryClient: d})

	require.NoError(t, err)
	assert.True(t, c.ValidatingSource.Available)
	assert.ErrorIs(t, c.MutatingSource.Err, ErrUnsupported)
}
