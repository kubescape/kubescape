package hostsensorutils

import (
	"context"
	"errors"
	"fmt"
	"testing"

	k8shostsensor "github.com/kubescape/k8s-interface/hostsensor"
	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/opa-utils/objectsenvelopes/hostsensor"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic/fake"
	k8stesting "k8s.io/client-go/testing"
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

	got, _, err := hsh.getCRDResources(context.Background(), k8shostsensor.KubeletConfiguration)

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
		query func(context.Context) ([]hostsensor.HostSensorDataEnvelope, crdCollection, error)
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
			got, _, err := tt.query(ctx)
			require.NoError(t, err)
			require.Len(t, got, 1)
			assert.Equal(t, "node-1", got[0].GetName())
			assert.Equal(t, tt.name, got[0].GetKind())
		})
	}
}

// Covers the scan sequence a node-agent restart produces: one scan collects
// nothing, the next one collects normally. With the cache enabled, the second
// scan must query the cluster instead of being served the empty first result.
func TestGetCRDResources_RecoversAfterEmptyCollection(t *testing.T) {
	withTempCacheDir(t)
	t.Setenv(HostSensorCacheTtlEnvVar, "1h")
	withK8sHost(t, "https://cluster-a.example.com")

	hsh := &HostSensorHandler{dynamicClient: newCRDDynamicClient(t)}
	got, collected, err := hsh.getKubeletInfo(context.Background())
	require.NoError(t, err)
	require.Empty(t, got)
	require.Zero(t, collected.listed)

	item := newCRDItem("KubeletInfo", "node-1", map[string]any{"KubeletInfo": map[string]any{"version": "v1.30.0"}})
	hsh.dynamicClient = newCRDDynamicClient(t, item)

	got, collected, err = hsh.getKubeletInfo(context.Background())
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Equal(t, 1, collected.listed)
	assert.Equal(t, "node-1", got[0].GetName())
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

// CollectResources must never return an error itself: every per-resource
// query failure is swallowed into infoMap so the caller keeps going. This
// exercises both the CloudProviderInfo failure arm and the per-resource
// addInfoToMap arm.
func TestCollectResources_RecordsQueryErrors(t *testing.T) {
	client := newCRDDynamicClient(t)
	client.PrependReactor("list", "kubeletinfos", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("boom")
	})
	client.PrependReactor("list", "cloudproviderinfos", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("cloud boom")
	})
	hsh := &HostSensorHandler{dynamicClient: client}

	res, infoMap, err := hsh.CollectResources(context.Background())

	require.NoError(t, err)
	assert.Empty(t, res)
	assert.Len(t, infoMap, 2)
}

func TestCollectResources_RecordsZeroItemsErrors(t *testing.T) {
	client := newCRDDynamicClient(t)
	// Empty client with no CRD items created, but simulate 1 node existing
	hsh := &HostSensorHandler{dynamicClient: client, nodeCount: 1}

	res, infoMap, err := hsh.CollectResources(context.Background())

	require.NoError(t, err)
	assert.Empty(t, res)
	assert.Len(t, infoMap, 9)
	for _, resource := range []k8shostsensor.HostSensorResource{
		k8shostsensor.OsReleaseFile,
		k8shostsensor.KernelVersion,
		k8shostsensor.LinuxSecurityHardeningStatus,
		k8shostsensor.OpenPortsList,
		k8shostsensor.LinuxKernelVariables,
		k8shostsensor.KubeletInfo,
		k8shostsensor.KubeProxyInfo,
		k8shostsensor.CNIInfo,
		k8shostsensor.ControlPlaneInfo,
	} {
		expectedErr := fmt.Sprintf("node-agent didn't report any %s for 1 nodes", resource.String())
		group, version := k8sinterface.SplitApiVersion(k8shostsensor.MapHostSensorResourceToApiGroup(resource))
		for _, r := range k8sinterface.ResourceGroupToString(group, version, resource.String()) {
			assert.Contains(t, infoMap, r)
			assert.Equal(t, expectedErr, infoMap[r].InnerInfo)
		}
	}
}

func hasKind(envelopes []hostsensor.HostSensorDataEnvelope, kind k8shostsensor.HostSensorResource) bool {
	for _, e := range envelopes {
		if e.GetKind() == kind.String() {
			return true
		}
	}
	return false
}
