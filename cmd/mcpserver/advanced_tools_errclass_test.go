package mcpserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/stretchr/testify/require"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	clienttesting "k8s.io/client-go/testing"
)

// advancedToolAPIErrors are API failures a live cluster can return, with the
// code an MCP client should see for each.
func advancedToolAPIErrors() []struct {
	name string
	err  error
	code ErrorCode
} {
	podsResource := schema.GroupResource{Resource: "pods"}
	return []struct {
		name string
		err  error
		code ErrorCode
	}{
		{"forbidden", apierrors.NewForbidden(podsResource, "app", errors.New("rbac")), ErrCodeRBACDenied},
		{"not found", apierrors.NewNotFound(podsResource, "app"), ErrCodeResourceNotFound},
		{"deadline exceeded", context.DeadlineExceeded, ErrCodeTimeout},
		{"canceled", context.Canceled, ErrCodeTimeout},
		{"api server failure", apierrors.NewInternalError(errors.New("boom")), ErrCodeK8sClientError},
		{"generic transport error", errors.New("connection refused"), ErrCodeK8sClientError},
	}
}

func TestScanResourceSlice_ClassifiesAPIErrors(t *testing.T) {
	for _, tc := range advancedToolAPIErrors() {
		t.Run(tc.name, func(t *testing.T) {
			dyn := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), map[schema.GroupVersionResource]string{podGVR: "PodList"})
			dyn.PrependReactor("list", "pods", func(clienttesting.Action) (bool, runtime.Object, error) {
				return true, nil, tc.err
			})
			ksServer := newTestMCPServerWithK8s(&k8sinterface.KubernetesApi{DynamicClient: dyn})

			result := registeredToolResult(t, dispatchRegisteredTool(t, ksServer, "scan_resource_slice", map[string]any{"resource_kind": "pods"}))
			require.True(t, result.IsError)
			var toolErr ToolError
			require.NoError(t, json.Unmarshal([]byte(toolResultText(t, result)), &toolErr))
			require.Equal(t, tc.code, toolErr.Code)
			require.Contains(t, toolErr.Message, "failed to list resources")
		})
	}
}

func TestDryRunRemediation_ClassifiesAPIErrors(t *testing.T) {
	for _, tc := range advancedToolAPIErrors() {
		t.Run(tc.name, func(t *testing.T) {
			dyn := dynamicfake.NewSimpleDynamicClient(runtime.NewScheme())
			dyn.PrependReactor("patch", "pods", func(clienttesting.Action) (bool, runtime.Object, error) {
				return true, nil, tc.err
			})
			ksServer := newTestMCPServerWithK8s(&k8sinterface.KubernetesApi{DynamicClient: dyn})

			result := registeredToolResult(t, dispatchRegisteredTool(t, ksServer, "dry_run_remediation", map[string]any{
				"resource_kind": "pods",
				"resource_name": "app",
				"namespace":     "default",
				"patch_json":    `{"metadata":{"labels":{"a":"b"}}}`,
			}))
			require.True(t, result.IsError)
			var toolErr ToolError
			require.NoError(t, json.Unmarshal([]byte(toolResultText(t, result)), &toolErr))
			require.Equal(t, tc.code, toolErr.Code)
			require.Contains(t, toolErr.Message, "dry-run patch failed")
		})
	}
}

func TestClassifyK8sAPIError(t *testing.T) {
	podsResource := schema.GroupResource{Resource: "pods"}
	forbidden := apierrors.NewForbidden(podsResource, "app", errors.New("rbac"))
	notFound := apierrors.NewNotFound(podsResource, "app")

	tests := []struct {
		name string
		err  error
		code ErrorCode
	}{
		{"wrapped forbidden", fmt.Errorf("patch: %w", forbidden), ErrCodeRBACDenied},
		{"wrapped not found", fmt.Errorf("get: %w", notFound), ErrCodeResourceNotFound},
		{"wrapped deadline exceeded", fmt.Errorf("list: %w", context.DeadlineExceeded), ErrCodeTimeout},
		{"internal api error", apierrors.NewInternalError(errors.New("boom")), ErrCodeK8sClientError},
		{"generic transport error", errors.New("connection refused"), ErrCodeK8sClientError},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.code, classifyK8sAPIError(tc.err))
		})
	}

	// Any code classifyScanError yields other than the scan-failure fallback
	// must pass through unchanged.
	for _, err := range []error{forbidden, notFound, context.Canceled} {
		code := classifyScanError(err)
		require.NotEqual(t, ErrCodeScanFailed, code)
		require.Equal(t, code, classifyK8sAPIError(err))
	}
}
