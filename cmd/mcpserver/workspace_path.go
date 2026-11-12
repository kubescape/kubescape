package mcpserver

import (
	"fmt"

	"github.com/kubescape/kubescape/v4/core/pkg/pathcontainment"
	"github.com/mark3labs/mcp-go/mcp"
)

// containToWorkspace confines a file path a tool argument names to the
// --workspace root, as path already is for local IaC scans. Tools that read a
// report or the files a report names must honour the same boundary; otherwise
// a client confined to the workspace for scans could still have files outside
// it read and their contents returned.
//
// Without a workspace (unconstrained mode) or for an empty argument the value
// is returned unchanged, so the tool's own validation and messages apply as
// before. A relative path resolves against the workspace, as it does for path.
func (ksServer *KubescapeMcpserver) containToWorkspace(argument, value string) (string, *mcp.CallToolResult) {
	if ksServer.workspaceDir == "" || value == "" {
		return value, nil
	}
	resolved, err := pathcontainment.ResolveContainedPath(ksServer.workspaceDir, value)
	if err != nil {
		return "", mcpToolError(ErrCodeInvalidArgument,
			fmt.Sprintf("invalid or unauthorized path: %s: %v", argument, err),
			map[string]any{"argument": argument})
	}
	return resolved, nil
}
