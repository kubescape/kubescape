package mcpserver

import (
	"context"
	"encoding/json"
	"testing"

	storagefake "github.com/kubescape/storage/pkg/generated/clientset/versioned/fake"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/runtime"
	k8stesting "k8s.io/client-go/testing"
)

func TestStorageToolsReportReadTimeout(t *testing.T) {
	for _, tc := range []struct {
		tool     string
		resource string
		args     map[string]any
	}{
		{"list_sboms", "sbomsyfts", nil},
		{"get_configuration_security_scan_manifest", "workloadconfigurationscans", map[string]any{"manifest_name": "scan"}},
		{"get_container_profile", "containerprofiles", map[string]any{"profile_name": "profile"}},
	} {
		for _, readErr := range []error{context.Canceled, context.DeadlineExceeded} {
			t.Run(tc.tool+"/"+readErr.Error(), func(t *testing.T) {
				client := storagefake.NewClientset()
				client.PrependReactor("list", tc.resource, func(k8stesting.Action) (bool, runtime.Object, error) {
					return true, nil, readErr
				})
				ks := &KubescapeMcpserver{ksClient: client.SpdxV1beta1()}

				req := mcp.CallToolRequest{}
				req.Params.Name = tc.tool
				req.Params.Arguments = tc.args
				// The CLI registers this wrapper, which classifies errors from CallTool.
				result, err := ks.toolHandler(tc.tool)(context.Background(), req)
				require.NoError(t, err)
				require.NotNil(t, result)
				require.True(t, result.IsError)

				var toolErr ToolError
				require.NoError(t, json.Unmarshal([]byte(toolResultText(t, result)), &toolErr))
				assert.Equal(t, ErrCodeTimeout, toolErr.Code)
				assert.Contains(t, toolErr.Message, readErr.Error())
				actions := client.Actions()
				require.Len(t, actions, 1, "stop after the failed list")
				assert.Equal(t, "list", actions[0].GetVerb())
				assert.Equal(t, tc.resource, actions[0].GetResource().Resource)
			})
		}
	}
}
