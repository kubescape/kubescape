package hostsensorutils

import (
	"context"
	"encoding/json"
	"testing"

	k8shostsensor "github.com/kubescape/k8s-interface/hostsensor"
	"github.com/kubescape/opa-utils/objectsenvelopes/hostsensor"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic/fake"
)

func TestConvertCRDToEnvelope(t *testing.T) {
	tests := []struct {
		name         string
		resourceType k8shostsensor.HostSensorResource
		object       map[string]interface{}
		wantData     map[string]interface{}
		wantErr      string
	}{
		{
			name:         "maps spec to envelope data and removes nodeName",
			resourceType: k8shostsensor.OsReleaseFile,
			object: map[string]interface{}{
				"metadata": map[string]interface{}{"name": "node-1"},
				"spec": map[string]interface{}{
					"nodeName": "node-1",
					"pretty":   "Ubuntu",
				},
			},
			wantData: map[string]interface{}{"pretty": "Ubuntu"},
		},
		{
			name:         "unwraps nested resource data",
			resourceType: k8shostsensor.KubeletInfo,
			object: map[string]interface{}{
				"metadata": map[string]interface{}{"name": "node-2"},
				"spec": map[string]interface{}{
					"KubeletInfo": map[string]interface{}{"version": "v1.30.0"},
				},
			},
			wantData: map[string]interface{}{"version": "v1.30.0"},
		},
		{
			name:         "missing spec returns error",
			resourceType: k8shostsensor.KernelVersion,
			object: map[string]interface{}{
				"metadata": map[string]interface{}{"name": "node-3"},
			},
			wantErr: "spec not found in CRD",
		},
	}

	hsh := &HostSensorHandler{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := hsh.convertCRDToEnvelope(unstructured.Unstructured{Object: tt.object}, tt.resourceType)
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.resourceType.String(), got.GetKind())
			assert.Equal(t, "hostdata.kubescape.cloud/v1beta0", got.GetApiVersion())
			require.JSONEq(t, mustJSON(t, tt.wantData), string(got.GetData()))
		})
	}
}

func TestHasCloudProviderInfo(t *testing.T) {
	tests := []struct {
		name string
		data []string
		want bool
	}{
		{
			name: "true when provider metadata API access is true",
			data: []string{`{"providerMetaDataAPIAccess":true}`},
			want: true,
		},
		{
			name: "false when provider metadata API access is false",
			data: []string{`{"providerMetaDataAPIAccess":false}`},
		},
		{
			name: "false for malformed envelope data",
			data: []string{`not-json`},
		},
		{
			name: "true when any envelope has provider access",
			data: []string{`{"providerMetaDataAPIAccess":false}`, `{"providerMetaDataAPIAccess":true}`},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			envelopes := make([]hostsensor.HostSensorDataEnvelope, 0, len(tt.data))
			for _, data := range tt.data {
				envelope := hostsensor.HostSensorDataEnvelope{}
				envelope.SetData([]byte(data))
				envelopes = append(envelopes, envelope)
			}

			assert.Equal(t, tt.want, hasCloudProviderInfo(envelopes))
		})
	}
}

func TestListCRDResources(t *testing.T) {
	item := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": hostDataGroup + "/" + hostDataVersion,
			"kind":       "OsReleaseFile",
			"metadata": map[string]interface{}{
				"name": "node-1",
			},
		},
	}
	hsh := &HostSensorHandler{
		dynamicClient: fake.NewSimpleDynamicClient(runtime.NewScheme(), item),
	}

	got, err := hsh.listCRDResources(context.Background(), "osreleasefiles", k8shostsensor.OsReleaseFile.String())

	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Equal(t, "node-1", got[0].GetName())
}

func TestHostSensorHandlerLifecycleEdges(t *testing.T) {
	handler := &HostSensorHandler{}

	assert.NoError(t, handler.TearDown())

	got, err := NewHostSensorHandler(nil, "")
	require.Nil(t, got)
	require.ErrorContains(t, err, "nil k8s interface received")
}

func mustJSON(t *testing.T, value map[string]interface{}) string {
	t.Helper()

	out, err := json.Marshal(value)
	require.NoError(t, err)
	return string(out)
}

func TestInitAllowsEmptyCRDList(t *testing.T) {
	hsh := &HostSensorHandler{
		dynamicClient: fake.NewSimpleDynamicClientWithCustomListKinds(
			runtime.NewScheme(),
			map[schema.GroupVersionResource]string{
				{Group: hostDataGroup, Version: hostDataVersion, Resource: "osreleasefiles"}: "OsReleaseFileList",
			},
		),
	}

	err := hsh.Init(context.Background())

	require.NoError(t, err)
}

func TestConvertCRDToEnvelopeKeepsObjectMetadataName(t *testing.T) {
	item := unstructured.Unstructured{}
	item.SetName("node-from-metadata")
	require.NoError(t, unstructured.SetNestedMap(item.Object, map[string]interface{}{"value": "5.15.0"}, "spec"))

	got, err := (&HostSensorHandler{}).convertCRDToEnvelope(item, k8shostsensor.KernelVersion)

	require.NoError(t, err)
	assert.Equal(t, "node-from-metadata", got.GetName())
}
