package mcpserver

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/mark3labs/mcp-go/server"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kubescape/kubescape/v4/core/pkg/pathcontainment"
)

func TestWorkspaceContainment_FlagsAndEnv(t *testing.T) {
	tempWorkspace := t.TempDir()
	tempFile := filepath.Join(tempWorkspace, "somefile.txt")
	require.NoError(t, os.WriteFile(tempFile, []byte("content"), 0600))

	nonExistentDir := filepath.Join(tempWorkspace, "does-not-exist")

	t.Run("non-existent workspace directory rejected", func(t *testing.T) {
		err := mcpServerEntrypoint(context.Background(), "invalid", 8080, nonExistentDir)
		// Option validation happens before workspace directory check
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported transport 'invalid'")

		// With valid transport, workspace validation runs and fails
		err = mcpServerEntrypoint(context.Background(), "stdio", 8080, nonExistentDir)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to resolve workspace directory")
	})

	t.Run("workspace file instead of directory rejected", func(t *testing.T) {
		err := mcpServerEntrypoint(context.Background(), "stdio", 8080, tempFile)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "is not a directory")
	})

	t.Run("env variable KUBESCAPE_WORKSPACE_DIR used when flag empty", func(t *testing.T) {
		t.Setenv("KUBESCAPE_WORKSPACE_DIR", nonExistentDir)
		err := mcpServerEntrypoint(context.Background(), "stdio", 8080, "")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to resolve workspace directory")
	})

	t.Run("flag overrides KUBESCAPE_WORKSPACE_DIR", func(t *testing.T) {
		t.Setenv("KUBESCAPE_WORKSPACE_DIR", tempWorkspace)
		// Non-existent flag should take precedence and fail
		err := mcpServerEntrypoint(context.Background(), "stdio", 8080, nonExistentDir)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to resolve workspace directory")
	})

	t.Run("valid workspace flag sets up cobra command", func(t *testing.T) {
		cmd := GetMCPServerCmd()
		flag := cmd.Flag("workspace")
		require.NotNil(t, flag)
		assert.Equal(t, "", flag.DefValue)
		assert.Contains(t, flag.Usage, "KUBESCAPE_WORKSPACE_DIR")
	})
}

func TestWorkspaceContainment_RunIaCScan(t *testing.T) {
	tempWorkspace := t.TempDir()
	manifestPath := filepath.Join(tempWorkspace, "deployment.yaml")
	require.NoError(t, os.WriteFile(manifestPath, []byte(privilegedPodManifest), 0600))

	// Create outside file
	outsideDir := t.TempDir()
	outsideManifest := filepath.Join(outsideDir, "outside.yaml")
	require.NoError(t, os.WriteFile(outsideManifest, []byte(privilegedPodManifest), 0600))

	// Create symlink inside workspace pointing outside
	symlinkPath := filepath.Join(tempWorkspace, "symlink-outside.yaml")
	require.NoError(t, os.Symlink(outsideManifest, symlinkPath))

	t.Run("contained path inside workspace is permitted", func(t *testing.T) {
		srv := &KubescapeMcpserver{
			workspaceDir: tempWorkspace,
			policyGetter: getSharedLiveClusterPolicyGetter(t),
		}
		// Manifest in workspace should pass containment and proceed to scan
		respBytes, err := srv.runIaCScan(context.Background(), "deployment.yaml", "nsa")
		if err != nil {
			// Even if scanning encounters an error, it must NOT be a path escape error
			assert.False(t, errors.Is(err, pathcontainment.ErrPathEscapesWorkspace))
		} else {
			assert.NotEmpty(t, respBytes)
		}
	})

	t.Run("traversal path escaping workspace is rejected", func(t *testing.T) {
		srv := &KubescapeMcpserver{
			workspaceDir: tempWorkspace,
		}
		_, err := srv.runIaCScan(context.Background(), "../../etc/shadow", "nsa")
		require.Error(t, err)
		assert.True(t, errors.Is(err, pathcontainment.ErrPathEscapesWorkspace), "expected ErrPathEscapesWorkspace, got: %v", err)
	})

	t.Run("absolute path outside workspace is rejected", func(t *testing.T) {
		srv := &KubescapeMcpserver{
			workspaceDir: tempWorkspace,
		}
		_, err := srv.runIaCScan(context.Background(), outsideManifest, "nsa")
		require.Error(t, err)
		assert.True(t, errors.Is(err, pathcontainment.ErrPathEscapesWorkspace), "expected ErrPathEscapesWorkspace, got: %v", err)
	})

	t.Run("symlink escaping workspace is rejected", func(t *testing.T) {
		srv := &KubescapeMcpserver{
			workspaceDir: tempWorkspace,
		}
		_, err := srv.runIaCScan(context.Background(), symlinkPath, "nsa")
		require.Error(t, err)
		assert.True(t, errors.Is(err, pathcontainment.ErrPathEscapesWorkspace), "expected ErrPathEscapesWorkspace, got: %v", err)
	})

	t.Run("unconstrained mode allows external path", func(t *testing.T) {
		srv := &KubescapeMcpserver{
			workspaceDir: "", // unconstrained
			policyGetter: getSharedLiveClusterPolicyGetter(t),
		}
		// Unconstrained mode does not reject outsideManifest with ErrPathEscapesWorkspace
		_, err := srv.runIaCScan(context.Background(), outsideManifest, "nsa")
		if err != nil {
			assert.False(t, errors.Is(err, pathcontainment.ErrPathEscapesWorkspace))
		}
	})
}

func TestWorkspaceContainment_RunIaCScanControls(t *testing.T) {
	tempWorkspace := t.TempDir()
	manifestPath := filepath.Join(tempWorkspace, "deployment.yaml")
	require.NoError(t, os.WriteFile(manifestPath, []byte(privilegedPodManifest), 0600))

	outsideDir := t.TempDir()
	outsideManifest := filepath.Join(outsideDir, "outside.yaml")
	require.NoError(t, os.WriteFile(outsideManifest, []byte(privilegedPodManifest), 0600))

	t.Run("runIaCScanControls rejects escaping path", func(t *testing.T) {
		srv := &KubescapeMcpserver{
			workspaceDir: tempWorkspace,
		}
		_, err := srv.runIaCScanControls(context.Background(), outsideManifest, []string{"C-0012"})
		require.Error(t, err)
		assert.True(t, errors.Is(err, pathcontainment.ErrPathEscapesWorkspace))
	})

	t.Run("runIaCScanControlsReport rejects escaping path", func(t *testing.T) {
		srv := &KubescapeMcpserver{
			workspaceDir: tempWorkspace,
		}
		_, err := srv.runIaCScanControlsReport(context.Background(), outsideManifest, []string{"C-0012"})
		require.Error(t, err)
		assert.True(t, errors.Is(err, pathcontainment.ErrPathEscapesWorkspace))
	})

	t.Run("unconstrained mode allows external path in controls scan", func(t *testing.T) {
		srv := &KubescapeMcpserver{
			workspaceDir: "",
			policyGetter: getSharedLiveClusterPolicyGetter(t),
		}
		_, err := srv.runIaCScanControls(context.Background(), outsideManifest, []string{"C-0012"})
		if err != nil {
			assert.False(t, errors.Is(err, pathcontainment.ErrPathEscapesWorkspace))
		}
	})
}

func TestWorkspaceContainment_RunWorkloadScan(t *testing.T) {
	tempWorkspace := t.TempDir()
	outsideDir := t.TempDir()
	outsideManifest := filepath.Join(outsideDir, "outside.yaml")
	require.NoError(t, os.WriteFile(outsideManifest, []byte(privilegedPodManifest), 0600))

	t.Run("rejects local manifest escaping workspace", func(t *testing.T) {
		srv := &KubescapeMcpserver{
			workspaceDir: tempWorkspace,
		}
		_, err := srv.RunWorkloadScan(context.Background(), "pod/privileged-pod", "default", outsideManifest, "nsa")
		require.Error(t, err)
		assert.True(t, errors.Is(err, pathcontainment.ErrPathEscapesWorkspace))
	})

	t.Run("unconstrained mode allows external manifest", func(t *testing.T) {
		srv := &KubescapeMcpserver{
			workspaceDir: "",
			policyGetter: getSharedLiveClusterPolicyGetter(t),
		}
		_, err := srv.RunWorkloadScan(context.Background(), "pod/privileged-pod", "default", outsideManifest, "nsa")
		if err != nil {
			assert.False(t, errors.Is(err, pathcontainment.ErrPathEscapesWorkspace))
		}
	})
}

func TestWorkspaceContainment_ErrorClassification(t *testing.T) {
	// ErrPathEscapesWorkspace classification
	code := classifyScanError(pathcontainment.ErrPathEscapesWorkspace)
	assert.Equal(t, ErrCodeInvalidArgument, code)

	msg := classifyScanErrorMessage(code, "IaC", pathcontainment.ErrPathEscapesWorkspace)
	assert.Contains(t, msg, "invalid or unauthorized path")

	// ErrInvalidPath classification
	codeInvalid := classifyScanError(pathcontainment.ErrInvalidPath)
	assert.Equal(t, ErrCodeInvalidArgument, codeInvalid)

	msgInvalid := classifyScanErrorMessage(codeInvalid, "IaC", pathcontainment.ErrInvalidPath)
	assert.Contains(t, msgInvalid, "invalid or unauthorized path")
}

func TestWorkspaceContainment_CallTool_ScanLocalIaC(t *testing.T) {
	tempWorkspace := t.TempDir()
	outsideDir := t.TempDir()
	outsideManifest := filepath.Join(outsideDir, "outside.yaml")
	require.NoError(t, os.WriteFile(outsideManifest, []byte(privilegedPodManifest), 0600))

	ksServer := &KubescapeMcpserver{
		s:            server.NewMCPServer("kubescape-test", "test"),
		workspaceDir: tempWorkspace,
	}
	createIaCScanningTools(ksServer)

	// Call scan_local_iac with an unauthorized path
	res, err := ksServer.CallTool(context.Background(), "scan_local_iac", map[string]any{
		"path": outsideManifest,
	})
	require.NoError(t, err, "path violations should be reported as MCP tool errors")
	require.NotNil(t, res)
	assert.True(t, res.IsError, "expected tool error")

	te := toolErrorOf(t, res)
	assert.Equal(t, ErrCodeInvalidArgument, te.Code)
	assert.Contains(t, te.Message, "invalid or unauthorized path")
}
