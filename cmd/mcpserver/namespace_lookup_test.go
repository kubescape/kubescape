package mcpserver

import (
	"context"
	"encoding/json"
	"testing"

	storagev1beta1 "github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	storagefake "github.com/kubescape/storage/pkg/generated/clientset/versioned/fake"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	k8stesting "k8s.io/client-go/testing"
)

func objectMeta(namespace, name string) metav1.ObjectMeta {
	return metav1.ObjectMeta{Namespace: namespace, Name: name}
}

func TestGetToolsFindNamespaceByName(t *testing.T) {
	client := storagefake.NewClientset(
		// Stored in the workload's namespace, as node-agent and httphandler do.
		&storagev1beta1.ContainerProfile{ObjectMeta: objectMeta("shop", "replicaset-web-5d8f-web")},
		&storagev1beta1.ContainerProfile{ObjectMeta: objectMeta("team-a", "replicaset-api-77c4-api")},
		&storagev1beta1.ContainerProfile{ObjectMeta: objectMeta("team-b", "replicaset-api-77c4-api")},
		&storagev1beta1.WorkloadConfigurationScan{ObjectMeta: objectMeta("shop", "deployment-web")},
		&storagev1beta1.WorkloadConfigurationScan{ObjectMeta: objectMeta("team-a", "deployment-api")},
		&storagev1beta1.WorkloadConfigurationScan{ObjectMeta: objectMeta("team-b", "deployment-api")},
	)
	var selectors []string
	for _, resource := range []string{"containerprofiles", "workloadconfigurationscans"} {
		client.PrependReactor("list", resource, func(action k8stesting.Action) (bool, runtime.Object, error) {
			selectors = append(selectors, action.(k8stesting.ListActionImpl).GetListOptions().FieldSelector)
			return false, nil, nil
		})
	}
	ks := &KubescapeMcpserver{ksClient: client.SpdxV1beta1()}

	for _, tc := range []struct {
		tool, nameArg, name string
	}{
		{"get_container_profile", "profile_name", "replicaset-web-5d8f-web"},
		{"get_configuration_security_scan_manifest", "manifest_name", "deployment-web"},
	} {
		for label, args := range map[string]map[string]any{
			"omitted": {tc.nameArg: tc.name},
			"null":    {tc.nameArg: tc.name, "namespace": nil},
			"empty":   {tc.nameArg: tc.name, "namespace": ""},
		} {
			t.Run(tc.tool+"/"+label, func(t *testing.T) {
				selectors = nil
				result, err := ks.CallTool(context.Background(), tc.tool, args)
				require.NoError(t, err)
				require.False(t, result.IsError, toolResultText(t, result))
				var got struct{ Metadata metav1.ObjectMeta }
				require.NoError(t, json.Unmarshal([]byte(toolResultText(t, result)), &got))
				assert.Equal(t, "shop", got.Metadata.Namespace)
				assert.Equal(t, tc.name, got.Metadata.Name)
				assert.Equal(t, []string{"metadata.name=" + tc.name}, selectors)
			})
		}
	}
}

func TestGetToolsNamespaceLookupErrors(t *testing.T) {
	client := storagefake.NewClientset(
		&storagev1beta1.ContainerProfile{ObjectMeta: objectMeta("team-a", "replicaset-api-77c4-api")},
		&storagev1beta1.ContainerProfile{ObjectMeta: objectMeta("team-b", "replicaset-api-77c4-api")},
		&storagev1beta1.WorkloadConfigurationScan{ObjectMeta: objectMeta("team-a", "deployment-api")},
		&storagev1beta1.WorkloadConfigurationScan{ObjectMeta: objectMeta("team-b", "deployment-api")},
	)
	ks := &KubescapeMcpserver{ksClient: client.SpdxV1beta1()}

	for _, tc := range []struct {
		name  string
		tool  string
		args  map[string]any
		code  ErrorCode
		parts []string
	}{
		{"profile in two namespaces", "get_container_profile", map[string]any{"profile_name": "replicaset-api-77c4-api"},
			ErrCodeAmbiguousResource, []string{"team-a, team-b", "set namespace"}},
		{"manifest in two namespaces", "get_configuration_security_scan_manifest", map[string]any{"manifest_name": "deployment-api"},
			ErrCodeAmbiguousResource, []string{"team-a, team-b", "set namespace"}},
		{"missing profile", "get_container_profile", map[string]any{"profile_name": "replicaset-gone-1-gone"},
			ErrCodeResourceNotFound, []string{`no container profile named "replicaset-gone-1-gone" in any namespace`}},
		{"missing manifest", "get_configuration_security_scan_manifest", map[string]any{"manifest_name": "deployment-gone"},
			ErrCodeResourceNotFound, []string{`no configuration manifest named "deployment-gone" in any namespace`}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result, err := ks.CallTool(context.Background(), tc.tool, tc.args)
			require.NoError(t, err)
			require.True(t, result.IsError)
			var toolErr ToolError
			require.NoError(t, json.Unmarshal([]byte(toolResultText(t, result)), &toolErr))
			assert.Equal(t, tc.code, toolErr.Code)
			for _, part := range tc.parts {
				assert.Contains(t, toolErr.Message, part)
			}
		})
	}

	// With a namespace the object is read from it directly, as before.
	result, err := ks.CallTool(context.Background(), "get_container_profile",
		map[string]any{"namespace": "team-b", "profile_name": "replicaset-api-77c4-api"})
	require.NoError(t, err)
	require.False(t, result.IsError, toolResultText(t, result))
	assert.Contains(t, toolResultText(t, result), `"namespace":"team-b"`)
}
