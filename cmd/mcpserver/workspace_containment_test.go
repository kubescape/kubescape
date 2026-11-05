package mcpserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/mark3labs/mcp-go/server"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kubescape/kubescape/v4/core/pkg/pathcontainment"
)

const outsideLeakManifest = `apiVersion: v1
kind: Pod
metadata:
  name: outside-leak-pod
spec:
  containers:
  - name: myapp
    image: nginx
    securityContext:
      privileged: true
`

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

	t.Run("workspace flag is forwarded from cobra command to entrypoint", func(t *testing.T) {
		cmd := GetMCPServerCmd()
		cmd.SetArgs([]string{"--workspace", nonExistentDir})
		err := cmd.Execute()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to resolve workspace directory")
	})

	t.Run("symlink parent traversal in workspace path resolves correctly", func(t *testing.T) {
		subDir := filepath.Join(tempWorkspace, "sub")
		require.NoError(t, os.Mkdir(subDir, 0755))
		deepDir := filepath.Join(subDir, "deep")
		require.NoError(t, os.MkdirAll(deepDir, 0755))
		symlinkTarget := filepath.Join(tempWorkspace, "link")
		if err := os.Symlink(deepDir, symlinkTarget); err != nil {
			t.Skipf("skipping symlink test: %v", err)
		}
		// link/.. should physically resolve to sub, not the lexical parent tempWorkspace
		resolved, err := pathcontainment.ResolveBaseDir(symlinkTarget + string(filepath.Separator) + "..")
		require.NoError(t, err)
		canonSub, err := filepath.EvalSymlinks(subDir)
		require.NoError(t, err)
		assert.Equal(t, canonSub, resolved)
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

	t.Run("contained path inside workspace is permitted", func(t *testing.T) {
		srv := &KubescapeMcpserver{
			workspaceDir: tempWorkspace,
			policyGetter: getSharedLiveClusterPolicyGetter(t),
		}
		respBytes, err := srv.runIaCScan(context.Background(), "deployment.yaml", "nsa")
		require.NoError(t, err)
		assert.NotEmpty(t, respBytes)
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
		symlinkPath := filepath.Join(tempWorkspace, "symlink-outside.yaml")
		if err := os.Symlink(outsideManifest, symlinkPath); err != nil {
			t.Skipf("skipping symlink test: %v", err)
		}
		srv := &KubescapeMcpserver{
			workspaceDir: tempWorkspace,
		}
		_, err := srv.runIaCScan(context.Background(), symlinkPath, "nsa")
		require.Error(t, err)
		assert.True(t, errors.Is(err, pathcontainment.ErrPathEscapesWorkspace), "expected ErrPathEscapesWorkspace, got: %v", err)
	})

	t.Run("directory scan skips symlinks pointing outside workspace", func(t *testing.T) {
		scanSubDir := filepath.Join(tempWorkspace, "scandir")
		require.NoError(t, os.Mkdir(scanSubDir, 0755))
		containedFile := filepath.Join(scanSubDir, "valid.yaml")
		require.NoError(t, os.WriteFile(containedFile, []byte(privilegedPodManifest), 0600))

		outsideLeak := filepath.Join(outsideDir, "outside-leak.yaml")
		require.NoError(t, os.WriteFile(outsideLeak, []byte(outsideLeakManifest), 0600))

		leakSymlink := filepath.Join(scanSubDir, "leak.yaml")
		if err := os.Symlink(outsideLeak, leakSymlink); err != nil {
			t.Skipf("skipping symlink test: %v", err)
		}

		srv := &KubescapeMcpserver{
			workspaceDir: tempWorkspace,
			policyGetter: getSharedLiveClusterPolicyGetter(t),
		}
		// Directory scan should succeed by scanning contained valid.yaml and skipping leak.yaml
		respBytes, err := srv.runIaCScan(context.Background(), "scandir", "nsa")
		require.NoError(t, err)
		assert.NotEmpty(t, respBytes)
		assert.Contains(t, string(respBytes), "privileged-pod")
		assert.NotContains(t, string(respBytes), "outside-leak-pod")
	})

	t.Run("kustomize configuration referencing outside resource is rejected", func(t *testing.T) {
		kustDir := filepath.Join(tempWorkspace, "kustomize-leak")
		require.NoError(t, os.Mkdir(kustDir, 0755))
		kustContent := fmt.Sprintf("apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\nresources:\n- %s\n", outsideManifest)
		require.NoError(t, os.WriteFile(filepath.Join(kustDir, "kustomization.yaml"), []byte(kustContent), 0600))

		srv := &KubescapeMcpserver{
			workspaceDir: tempWorkspace,
			policyGetter: getSharedLiveClusterPolicyGetter(t),
		}
		_, err := srv.runIaCScan(context.Background(), "kustomize-leak", "nsa")
		require.Error(t, err)
		assert.True(t, errors.Is(err, pathcontainment.ErrPathEscapesWorkspace), "expected ErrPathEscapesWorkspace for escaping Kustomize reference, got: %v", err)
	})

	t.Run("kustomize configuration referencing helm chart with outside symlink is rejected", func(t *testing.T) {
		kustDir := filepath.Join(tempWorkspace, "kustomize-helm-leak")
		require.NoError(t, os.MkdirAll(filepath.Join(kustDir, "charts", "mychart", "templates"), 0755))
		require.NoError(t, os.WriteFile(filepath.Join(kustDir, "charts", "mychart", "Chart.yaml"), []byte("apiVersion: v2\nname: mychart\nversion: 0.1.0\n"), 0600))
		require.NoError(t, os.WriteFile(filepath.Join(kustDir, "charts", "mychart", "values.yaml"), []byte("{}\n"), 0600))

		leakSymlink := filepath.Join(kustDir, "charts", "mychart", "templates", "leak.yaml")
		if err := os.Symlink(outsideManifest, leakSymlink); err != nil {
			t.Skipf("skipping symlink test: %v", err)
		}

		kustContent := "apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\nhelmCharts:\n- name: mychart\n  releaseName: mychart\n"
		require.NoError(t, os.WriteFile(filepath.Join(kustDir, "kustomization.yaml"), []byte(kustContent), 0600))

		srv := &KubescapeMcpserver{
			workspaceDir: tempWorkspace,
			policyGetter: getSharedLiveClusterPolicyGetter(t),
		}
		_, err := srv.runIaCScan(context.Background(), "kustomize-helm-leak", "nsa")
		require.Error(t, err)
		assert.True(t, errors.Is(err, pathcontainment.ErrPathEscapesWorkspace), "expected ErrPathEscapesWorkspace for escaping Helm chart template in Kustomize, got: %v", err)
	})

	t.Run("unconstrained mode allows external path", func(t *testing.T) {
		srv := &KubescapeMcpserver{
			workspaceDir: "", // unconstrained
			policyGetter: getSharedLiveClusterPolicyGetter(t),
		}
		respBytes, err := srv.runIaCScan(context.Background(), outsideManifest, "nsa")
		require.NoError(t, err)
		assert.NotEmpty(t, respBytes)
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

	t.Run("contained path inside workspace is permitted for runIaCScanControls", func(t *testing.T) {
		srv := &KubescapeMcpserver{
			workspaceDir: tempWorkspace,
			policyGetter: getSharedLiveClusterPolicyGetter(t),
		}
		respBytes, err := srv.runIaCScanControls(context.Background(), "deployment.yaml", []string{"C-0017"})
		require.NoError(t, err)
		assert.NotEmpty(t, respBytes)
	})

	t.Run("contained path inside workspace is permitted for runIaCScanControlsReport", func(t *testing.T) {
		srv := &KubescapeMcpserver{
			workspaceDir: tempWorkspace,
			policyGetter: getSharedLiveClusterPolicyGetter(t),
		}
		outcome, err := srv.runIaCScanControlsReport(context.Background(), "deployment.yaml", []string{"C-0017"})
		require.NoError(t, err)
		require.NotNil(t, outcome)
		assert.NotEmpty(t, outcome.ReportJSON)
	})

	t.Run("unconstrained mode allows external path in controls scan", func(t *testing.T) {
		srv := &KubescapeMcpserver{
			workspaceDir: "",
			policyGetter: getSharedLiveClusterPolicyGetter(t),
		}
		respBytes, err := srv.runIaCScanControls(context.Background(), outsideManifest, []string{"C-0012"})
		require.NoError(t, err)
		assert.NotEmpty(t, respBytes)
		var resp scanResponse
		require.NoError(t, json.Unmarshal(respBytes, &resp))
		assert.Positive(t, resp.TotalControls)
	})
}

func TestWorkspaceContainment_RunWorkloadScan(t *testing.T) {
	tempWorkspace := t.TempDir()
	manifestPath := filepath.Join(tempWorkspace, "deployment.yaml")
	require.NoError(t, os.WriteFile(manifestPath, []byte(privilegedPodManifest), 0600))

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

	t.Run("contained local manifest inside workspace is permitted", func(t *testing.T) {
		srv := &KubescapeMcpserver{
			workspaceDir: tempWorkspace,
			policyGetter: getSharedLiveClusterPolicyGetter(t),
		}
		respBytes, err := srv.RunWorkloadScan(context.Background(), "pod/privileged-pod", "default", manifestPath, "nsa")
		require.NoError(t, err)
		assert.NotEmpty(t, respBytes)
	})

	t.Run("unconstrained mode allows external manifest", func(t *testing.T) {
		srv := &KubescapeMcpserver{
			workspaceDir: "",
			policyGetter: getSharedLiveClusterPolicyGetter(t),
		}
		respBytes, err := srv.RunWorkloadScan(context.Background(), "pod/privileged-pod", "default", outsideManifest, "nsa")
		require.NoError(t, err)
		assert.NotEmpty(t, respBytes)
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

func TestWorkspaceContainment_CallTool(t *testing.T) {
	tempWorkspace := t.TempDir()
	outsideDir := t.TempDir()
	outsideManifest := filepath.Join(outsideDir, "outside.yaml")
	require.NoError(t, os.WriteFile(outsideManifest, []byte(privilegedPodManifest), 0600))

	ksServer := &KubescapeMcpserver{
		s:            server.NewMCPServer("kubescape-test", "test"),
		workspaceDir: tempWorkspace,
	}
	createIaCScanningTools(ksServer)
	createWorkloadScanningTools(ksServer)

	t.Run("scan_local_iac rejects path outside workspace", func(t *testing.T) {
		res, err := ksServer.CallTool(context.Background(), "scan_local_iac", map[string]any{
			"path": outsideManifest,
		})
		require.NoError(t, err, "path violations should be reported as MCP tool errors")
		require.NotNil(t, res)
		assert.True(t, res.IsError, "expected tool error")

		te := toolErrorOf(t, res)
		assert.Equal(t, ErrCodeInvalidArgument, te.Code)
		assert.Contains(t, te.Message, "invalid or unauthorized path")
	})

	t.Run("scan_local_iac_controls rejects path outside workspace", func(t *testing.T) {
		res, err := ksServer.CallTool(context.Background(), "scan_local_iac_controls", map[string]any{
			"path":        outsideManifest,
			"control_ids": "C-0012",
		})
		require.NoError(t, err, "path violations should be reported as MCP tool errors")
		require.NotNil(t, res)
		assert.True(t, res.IsError, "expected tool error")

		te := toolErrorOf(t, res)
		assert.Equal(t, ErrCodeInvalidArgument, te.Code)
		assert.Contains(t, te.Message, "invalid or unauthorized path")
	})

	t.Run("scan_workload with local manifest rejects path outside workspace", func(t *testing.T) {
		res, err := ksServer.CallTool(context.Background(), "scan_workload", map[string]any{
			"workload": "pod/privileged-pod",
			"path":     outsideManifest,
		})
		require.NoError(t, err, "path violations should be reported as MCP tool errors")
		require.NotNil(t, res)
		assert.True(t, res.IsError, "expected tool error")

		te := toolErrorOf(t, res)
		assert.Equal(t, ErrCodeInvalidArgument, te.Code)
		assert.Contains(t, te.Message, "invalid or unauthorized path")
	})
}
