package hostsensorutils

import (
	"context"
	"testing"

	k8shostsensor "github.com/kubescape/k8s-interface/hostsensor"
	"github.com/kubescape/opa-utils/objectsenvelopes/hostsensor"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic/fake"
)

func newCRDItem(kind, name string, spec map[string]any) *unstructured.Unstructured {
	return &unstructured.Unstructured{
		Object: map[string]any{
			"apiVersion": hostDataGroup + "/" + hostDataVersion,
			"kind":       kind,
			"metadata": map[string]any{
				"name": name,
			},
			"spec": spec,
		},
	}
}

// newCRDDynamicClient builds a fake dynamic client with explicit GVR->ListKind
// mappings taken from MapResourceToPlural, since client-go's generic pluralization
// guesser gets resource names like "LinuxKernelVariables" wrong (already ends in "s").
//
// Items are added via Resource(gvr).Create rather than passed to the
// constructor: the tracker's Add() always (re-)derives the storage GVR from
// the object's kind using the same generic guesser, ignoring the custom
// gvrToListKind map, so constructor-supplied items would land under the
// wrong (guessed) resource.
func newCRDDynamicClient(t *testing.T, items ...*unstructured.Unstructured) *fake.FakeDynamicClient {
	t.Helper()

	allResources := []k8shostsensor.HostSensorResource{
		k8shostsensor.OsReleaseFile,
		k8shostsensor.KernelVersion,
		k8shostsensor.LinuxSecurityHardeningStatus,
		k8shostsensor.OpenPortsList,
		k8shostsensor.LinuxKernelVariables,
		k8shostsensor.KubeletInfo,
		k8shostsensor.KubeProxyInfo,
		k8shostsensor.ControlPlaneInfo,
		k8shostsensor.CloudProviderInfo,
		k8shostsensor.CNIInfo,
	}
	gvrToListKind := make(map[schema.GroupVersionResource]string, len(allResources))
	for _, resourceType := range allResources {
		gvr := schema.GroupVersionResource{
			Group:    hostDataGroup,
			Version:  hostDataVersion,
			Resource: k8shostsensor.MapResourceToPlural(resourceType),
		}
		gvrToListKind[gvr] = resourceType.String() + "List"
	}

	client := fake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), gvrToListKind)

	ctx := context.Background()
	for _, item := range items {
		gvr := schema.GroupVersionResource{
			Group:    hostDataGroup,
			Version:  hostDataVersion,
			Resource: k8shostsensor.MapResourceToPlural(k8shostsensor.HostSensorResource(item.GetKind())),
		}
		_, err := client.Resource(gvr).Create(ctx, item, metav1.CreateOptions{})
		require.NoError(t, err)
	}

	return client
}

func TestGetCRDResources_UnsupportedResourceType(t *testing.T) {
	hsh := &HostSensorHandler{}

	got, err := hsh.getCRDResources(context.Background(), k8shostsensor.KubeletConfiguration)

	require.Nil(t, got)
	require.ErrorContains(t, err, "unsupported resource type")
}

// Exercises getCRDResources indirectly through every thin per-resource getter,
// which each contribute their own (otherwise 0%) line of coverage.
func TestCRDResourceGetters(t *testing.T) {
	items := []*unstructured.Unstructured{
		newCRDItem("OsReleaseFile", "node-1", map[string]any{"pretty": "Ubuntu"}),
		newCRDItem("KernelVersion", "node-1", map[string]any{"version": "5.15.0"}),
		newCRDItem("LinuxSecurityHardeningStatus", "node-1", map[string]any{"apparmor": true}),
		newCRDItem("OpenPortsList", "node-1", map[string]any{"ports": []any{"80"}}),
		newCRDItem("LinuxKernelVariables", "node-1", map[string]any{"variables": map[string]any{}}),
		newCRDItem("KubeletInfo", "node-1", map[string]any{"KubeletInfo": map[string]any{"version": "v1.30.0"}}),
		newCRDItem("KubeProxyInfo", "node-1", map[string]any{"mode": "iptables"}),
		newCRDItem("ControlPlaneInfo", "node-1", map[string]any{"apiServerInfo": map[string]any{}}),
		newCRDItem("CloudProviderInfo", "node-1", map[string]any{"providerMetaDataAPIAccess": true}),
		newCRDItem("CNIInfo", "node-1", map[string]any{"cni": "calico"}),
	}
	hsh := &HostSensorHandler{
		dynamicClient: newCRDDynamicClient(t, items...),
	}
	ctx := context.Background()

	tests := []struct {
		name  string
		query func(context.Context) ([]hostsensor.HostSensorDataEnvelope, error)
	}{
		{"OsReleaseFile", hsh.getOsReleaseFile},
		{"KernelVersion", hsh.getKernelVersion},
		{"LinuxSecurityHardeningStatus", hsh.getLinuxSecurityHardeningStatus},
		{"OpenPortsList", hsh.getOpenPortsList},
		{"LinuxKernelVariables", hsh.getKernelVariables},
		{"KubeletInfo", hsh.getKubeletInfo},
		{"KubeProxyInfo", hsh.getKubeProxyInfo},
		{"ControlPlaneInfo", hsh.getControlPlaneInfo},
		{"CloudProviderInfo", hsh.getCloudProviderInfo},
		{"CNIInfo", hsh.getCNIInfo},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.query(ctx)
			require.NoError(t, err)
			require.Len(t, got, 1)
			assert.Equal(t, "node-1", got[0].GetName())
		})
	}
}

func TestCollectResources_SkipsControlPlaneInfoWhenCloudProviderPresent(t *testing.T) {
	items := []*unstructured.Unstructured{
		newCRDItem("CloudProviderInfo", "node-1", map[string]any{"providerMetaDataAPIAccess": true}),
		newCRDItem("ControlPlaneInfo", "node-1", map[string]any{"apiServerInfo": map[string]any{}}),
		newCRDItem("OsReleaseFile", "node-1", map[string]any{"pretty": "Ubuntu"}),
	}
	hsh := &HostSensorHandler{
		dynamicClient: newCRDDynamicClient(t, items...),
	}

	res, infoMap, err := hsh.CollectResources(context.Background())

	require.NoError(t, err)
	assert.Empty(t, infoMap)
	assert.False(t, hasKind(res, k8shostsensor.ControlPlaneInfo),
		"ControlPlaneInfo should be skipped when a cloud provider is detected")
	assert.True(t, hasKind(res, k8shostsensor.CloudProviderInfo))
	assert.True(t, hasKind(res, k8shostsensor.OsReleaseFile))
}

func TestCollectResources_IncludesControlPlaneInfoWithoutCloudProvider(t *testing.T) {
	items := []*unstructured.Unstructured{
		newCRDItem("CloudProviderInfo", "node-1", map[string]any{"providerMetaDataAPIAccess": false}),
		newCRDItem("ControlPlaneInfo", "node-1", map[string]any{"apiServerInfo": map[string]any{}}),
	}
	hsh := &HostSensorHandler{
		dynamicClient: newCRDDynamicClient(t, items...),
	}

	res, infoMap, err := hsh.CollectResources(context.Background())

	require.NoError(t, err)
	assert.Empty(t, infoMap)
	assert.True(t, hasKind(res, k8shostsensor.ControlPlaneInfo))
}

func hasKind(envelopes []hostsensor.HostSensorDataEnvelope, kind k8shostsensor.HostSensorResource) bool {
	for _, e := range envelopes {
		if e.GetKind() == kind.String() {
			return true
		}
	}
	return false
}

func TestNewHostSensorHandlerMock(t *testing.T) {
	mock := NewHostSensorHandlerMock()

	require.NotNil(t, mock)

	res, infoMap, err := mock.CollectResources(context.Background())
	require.NoError(t, err)
	assert.Nil(t, infoMap)
	assert.Empty(t, res)
}
