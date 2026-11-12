package fixhandler

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestPostRenderer_Validation(t *testing.T) {
	tmp := t.TempDir()

	err := EmitPostRenderer("", tmp)
	assert.Error(t, err, "Empty kustomizeDir must return error")
	assert.Contains(t, err.Error(), "kustomize directory cannot be empty")

	err = EmitPostRenderer(tmp, "")
	assert.Error(t, err, "Empty outputDir must return error")
	assert.Contains(t, err.Error(), "output directory cannot be empty")
}

func TestPostRenderer_ScriptGenerationAndPermissions(t *testing.T) {
	kustDir := t.TempDir()
	outDir := filepath.Join(t.TempDir(), "postrenderer")

	err := EmitPostRenderer(kustDir, outDir)
	require.NoError(t, err)

	shPath := filepath.Join(outDir, "renderer.sh")
	require.FileExists(t, shPath)

	info, err := os.Stat(shPath)
	require.NoError(t, err)

	// Verify executable permissions (0755) on POSIX platforms
	if runtime.GOOS != "windows" {
		assert.Equal(t, os.FileMode(0755), info.Mode().Perm(), "renderer.sh must have 0755 executable permissions")
	}

	shContent, err := os.ReadFile(shPath)
	require.NoError(t, err)
	shStr := string(shContent)
	assert.Contains(t, shStr, "#!/usr/bin/env bash")
	assert.Contains(t, shStr, "set -euo pipefail")
	assert.Contains(t, shStr, "kustomize build")
	assert.Contains(t, shStr, "mktemp -d")
	assert.Contains(t, shStr, `trap 'rm -rf "$WORK_DIR"' EXIT`)
	assert.Contains(t, shStr, "refusing to emit unpatched manifests")

	// Verify Windows batch script
	batPath := filepath.Join(outDir, "renderer.bat")
	require.FileExists(t, batPath)
	batContent, err := os.ReadFile(batPath)
	require.NoError(t, err)
	batStr := string(batContent)
	assert.Contains(t, batStr, "@echo off")
	assert.Contains(t, batStr, "kustomize build")
	assert.Contains(t, batStr, "refusing to emit unpatched manifests")
	assert.Contains(t, batStr, "exit /b 1")
	assert.Contains(t, batStr, "for /L %%I in (1,1,50) do")
	assert.Contains(t, batStr, "Join-Path $env:WORK_DIR 'all.yaml'")
	assert.Contains(t, batStr, "[Console]::OpenStandardInput()")
	assert.Contains(t, batStr, "$in.CopyTo($out)")
	assert.NotContains(t, batStr, "findstr \"^\"")
	assert.Contains(t, batStr, "failed to create exclusive temporary workspace")
	assert.Contains(t, batStr, "failed to read Helm manifest stream from stdin")
}

func TestPostRenderer_IsolatedStdinExecution(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Skipping bash script execution test on Windows")
	}
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash executable not found in PATH")
	}
	if _, err := exec.LookPath("kustomize"); err != nil {
		t.Skip("kustomize executable not found in PATH")
	}

	kustDir := t.TempDir()
	outDir := filepath.Join(kustDir, "renderer")
	require.NoError(t, os.MkdirAll(outDir, 0755))

	patchContent := `[
  {
    "op": "replace",
    "path": "/spec/template/spec/containers/0/securityContext/privileged",
    "value": false
  }
]`
	patchFileName := "apps-Deployment-default-nginx-12345678.yaml"
	require.NoError(t, os.WriteFile(filepath.Join(kustDir, patchFileName), []byte(patchContent), 0600))

	kustContent := `apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
  - base.yaml
patches:
  - path: apps-Deployment-default-nginx-12345678.yaml
    target:
      group: ^apps$
      version: ^v1$
      kind: ^Deployment$
      name: ^nginx$
      namespace: ^default$
`
	require.NoError(t, os.WriteFile(filepath.Join(kustDir, "kustomization.yaml"), []byte(kustContent), 0600))
	require.NoError(t, os.WriteFile(filepath.Join(kustDir, "base.yaml"), []byte("apiVersion: apps/v1\nkind: Deployment\n"), 0600))

	err := EmitPostRenderer(kustDir, outDir)
	require.NoError(t, err)

	shPath := filepath.Join(outDir, "renderer.sh")
	require.FileExists(t, shPath)

	helmStdinInput := `apiVersion: v1
kind: Service
metadata:
  name: nginx-svc
  namespace: default
spec:
  ports:
    - port: 80
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: nginx
  namespace: default
spec:
  template:
    spec:
      containers:
        - name: nginx
          image: nginx:1.21
          securityContext:
            privileged: true
`

	cmd := exec.Command(shPath)
	cmd.Stdin = strings.NewReader(helmStdinInput)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	runErr := cmd.Run()
	require.NoError(t, runErr, "renderer.sh execution failed: %s", stderr.String())

	output := stdout.String()
	assert.Contains(t, output, "privileged: false", "Kustomize patch must remediate privileged to false")
	assert.Contains(t, output, "nginx-svc", "Non-patched Service must pass through unmodified")

	kustAfter, err := os.ReadFile(filepath.Join(kustDir, "kustomization.yaml"))
	require.NoError(t, err)
	assert.Equal(t, kustContent, string(kustAfter), "kustomization.yaml must not be modified by post-renderer execution")
}

func TestPostRenderer_SpecialCharactersInPaths(t *testing.T) {
	// Path containing $, a single quote ('), and a lone %
	specialDirName := "kust_$_'dir%_test"
	baseDir := t.TempDir()
	kustDir := filepath.Join(baseDir, specialDirName)
	require.NoError(t, os.MkdirAll(kustDir, 0755))

	outDir := filepath.Join(kustDir, "renderer")
	require.NoError(t, os.MkdirAll(outDir, 0755))

	patchContent := `[
  {
    "op": "replace",
    "path": "/spec/template/spec/containers/0/securityContext/privileged",
    "value": false
  }
]`
	patchFileName := "apps-Deployment-default-nginx-12345678.yaml"
	require.NoError(t, os.WriteFile(filepath.Join(kustDir, patchFileName), []byte(patchContent), 0600))

	kustContent := fmt.Sprintf(`apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
  - base.yaml
patches:
  - path: %s
    target:
      group: ^apps$
      version: ^v1$
      kind: ^Deployment$
      name: ^nginx$
      namespace: ^default$
`, patchFileName)
	require.NoError(t, os.WriteFile(filepath.Join(kustDir, "kustomization.yaml"), []byte(kustContent), 0600))
	require.NoError(t, os.WriteFile(filepath.Join(kustDir, "base.yaml"), []byte("apiVersion: apps/v1\nkind: Deployment\n"), 0600))

	err := EmitPostRenderer(kustDir, outDir)
	require.NoError(t, err)

	// Verify batch script escaped % to %% in the kustomize path
	batPath := filepath.Join(outDir, "renderer.bat")
	batData, err := os.ReadFile(batPath)
	require.NoError(t, err)
	assert.Contains(t, string(batData), "dir%%_test", "batch script must escape % in the kustomize path as %%")

	// Verify bash script escaped using single quotes
	shPath := filepath.Join(outDir, "renderer.sh")
	shData, err := os.ReadFile(shPath)
	require.NoError(t, err)
	assert.Contains(t, string(shData), "KUST_DIR='", "bash script must quote path in single quotes")

	if runtime.GOOS == "windows" {
		t.Skip("Skipping bash execution on Windows")
	}
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash executable not found in PATH")
	}
	if _, err := exec.LookPath("kustomize"); err != nil {
		t.Skip("kustomize executable not found in PATH")
	}

	helmStdinInput := `apiVersion: apps/v1
kind: Deployment
metadata:
  name: nginx
  namespace: default
spec:
  template:
    spec:
      containers:
        - name: nginx
          image: nginx:1.21
          securityContext:
            privileged: true
`
	cmd := exec.Command(shPath)
	cmd.Stdin = strings.NewReader(helmStdinInput)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	runErr := cmd.Run()
	require.NoError(t, runErr, "renderer.sh execution failed for special path: %s", stderr.String())
	assert.Contains(t, stdout.String(), "privileged: false")
}

func TestPostRenderer_FailClosedWhenKustomizationMissing(t *testing.T) {
	kustDir := t.TempDir() // empty directory, no kustomization.yaml
	outDir := filepath.Join(t.TempDir(), "renderer")

	err := EmitPostRenderer(kustDir, outDir)
	require.NoError(t, err)

	shPath := filepath.Join(outDir, "renderer.sh")
	require.FileExists(t, shPath)

	batPath := filepath.Join(outDir, "renderer.bat")
	require.FileExists(t, batPath)
	batContent, err := os.ReadFile(batPath)
	require.NoError(t, err)
	assert.Contains(t, string(batContent), "refusing to emit unpatched manifests")
	assert.Contains(t, string(batContent), "exit /b 1")

	if runtime.GOOS == "windows" {
		t.Skip("Skipping bash execution on Windows")
	}
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash executable not found in PATH")
	}
	if _, err := exec.LookPath("kustomize"); err != nil {
		t.Skip("kustomize executable not found in PATH")
	}

	cmd := exec.Command(shPath)
	cmd.Stdin = strings.NewReader("apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: test\n")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	runErr := cmd.Run()
	require.Error(t, runErr, "renderer.sh must exit with error when kustomization.yaml is missing")
	assert.Contains(t, stderr.String(), "refusing to emit unpatched manifests")
}

func TestPostRenderer_EscapingSymlinkRejected(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Skipping symlink test on Windows")
	}

	outsideDir := t.TempDir()
	outsideSh := filepath.Join(outsideDir, "valuable-sh.txt")
	outsideBat := filepath.Join(outsideDir, "valuable-bat.txt")
	require.NoError(t, os.WriteFile(outsideSh, []byte("SENTINEL_SH"), 0600))
	require.NoError(t, os.WriteFile(outsideBat, []byte("SENTINEL_BAT"), 0600))

	kustDir := t.TempDir()
	outDir := filepath.Join(t.TempDir(), "scripts")
	require.NoError(t, os.MkdirAll(outDir, 0755))

	// Symlink renderer.sh to outside file
	require.NoError(t, os.Symlink(outsideSh, filepath.Join(outDir, "renderer.sh")))

	err := EmitPostRenderer(kustDir, outDir)
	require.Error(t, err, "EmitPostRenderer must reject writing to an existing symlink")
	assert.Contains(t, err.Error(), "symbolic link")

	// Sentinel file must remain completely uncorrupted and intact
	shContent, err := os.ReadFile(outsideSh)
	require.NoError(t, err)
	assert.Equal(t, "SENTINEL_SH", string(shContent), "outside sentinel file must not be modified or truncated")

	// Remove renderer.sh symlink and test renderer.bat symlink
	require.NoError(t, os.Remove(filepath.Join(outDir, "renderer.sh")))
	require.NoError(t, os.Symlink(outsideBat, filepath.Join(outDir, "renderer.bat")))

	err = EmitPostRenderer(kustDir, outDir)
	require.Error(t, err, "EmitPostRenderer must reject writing to an existing symlink for renderer.bat")
	assert.Contains(t, err.Error(), "symbolic link")

	batContent, err := os.ReadFile(outsideBat)
	require.NoError(t, err)
	assert.Equal(t, "SENTINEL_BAT", string(batContent), "outside sentinel file must not be modified or truncated")
}

func TestPostRenderer_SourceAllYamlDoesNotOverwriteHelmStdin(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Skipping bash execution on Windows")
	}
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash executable not found in PATH")
	}
	if _, err := exec.LookPath("kustomize"); err != nil {
		t.Skip("kustomize executable not found in PATH")
	}

	kustDir := t.TempDir()
	outDir := filepath.Join(kustDir, "renderer")
	require.NoError(t, os.MkdirAll(outDir, 0755))

	// Source directory contains an all.yaml file
	require.NoError(t, os.WriteFile(filepath.Join(kustDir, "all.yaml"), []byte("apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: stale-all-yaml\n"), 0600))

	patchContent := `[
  {
    "op": "replace",
    "path": "/spec/template/spec/containers/0/securityContext/privileged",
    "value": false
  }
]`
	patchFileName := "apps-Deployment-default-nginx-12345678.yaml"
	require.NoError(t, os.WriteFile(filepath.Join(kustDir, patchFileName), []byte(patchContent), 0600))

	kustContent := fmt.Sprintf(`apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
  - base.yaml
patches:
  - path: %s
    target:
      group: ^apps$
      version: ^v1$
      kind: ^Deployment$
      name: ^nginx$
      namespace: ^default$
`, patchFileName)
	require.NoError(t, os.WriteFile(filepath.Join(kustDir, "kustomization.yaml"), []byte(kustContent), 0600))
	require.NoError(t, os.WriteFile(filepath.Join(kustDir, "base.yaml"), []byte("apiVersion: apps/v1\nkind: Deployment\n"), 0600))

	err := EmitPostRenderer(kustDir, outDir)
	require.NoError(t, err)

	shPath := filepath.Join(outDir, "renderer.sh")
	require.FileExists(t, shPath)

	helmStdinInput := `apiVersion: apps/v1
kind: Deployment
metadata:
  name: nginx
  namespace: default
spec:
  template:
    spec:
      containers:
        - name: nginx
          image: nginx:1.21
          securityContext:
            privileged: true
`

	cmd := exec.Command(shPath)
	cmd.Stdin = strings.NewReader(helmStdinInput)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	runErr := cmd.Run()
	require.NoError(t, runErr, "renderer.sh execution failed: %s", stderr.String())

	output := stdout.String()
	assert.Contains(t, output, "privileged: false", "Kustomize patch must remediate privileged to false")
	assert.NotContains(t, output, "stale-all-yaml", "source all.yaml must NOT overwrite Helm stdin")
}

func TestPostRenderer_WindowsExecution(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Skipping Windows batch execution test on non-Windows")
	}
	if _, err := exec.LookPath("cmd.exe"); err != nil {
		t.Skip("cmd.exe not found in PATH")
	}
	if _, err := exec.LookPath("kustomize"); err != nil {
		t.Skip("kustomize executable not found in PATH")
	}

	kustDir := t.TempDir()
	outDir := filepath.Join(kustDir, "renderer")
	require.NoError(t, os.MkdirAll(outDir, 0755))

	patchContent := `[
  {
    "op": "replace",
    "path": "/spec/template/spec/containers/0/securityContext/privileged",
    "value": false
  }
]`
	patchFileName := "apps-Deployment-default-nginx-12345678.yaml"
	require.NoError(t, os.WriteFile(filepath.Join(kustDir, patchFileName), []byte(patchContent), 0600))

	kustContent := `apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
  - base.yaml
patches:
  - path: apps-Deployment-default-nginx-12345678.yaml
    target:
      group: ^apps$
      version: ^v1$
      kind: ^Deployment$
      name: ^nginx$
      namespace: ^default$
`
	require.NoError(t, os.WriteFile(filepath.Join(kustDir, "kustomization.yaml"), []byte(kustContent), 0600))
	require.NoError(t, os.WriteFile(filepath.Join(kustDir, "base.yaml"), []byte("apiVersion: apps/v1\nkind: Deployment\n"), 0600))

	err := EmitPostRenderer(kustDir, outDir)
	require.NoError(t, err)

	batPath := filepath.Join(outDir, "renderer.bat")
	require.FileExists(t, batPath)

	// Long line (16 KiB) to verify bytes-oriented stdin streaming without findstr 8 KiB line limit
	longSecretToken := strings.Repeat("A", 16384)
	helmStdinInput := fmt.Sprintf(`apiVersion: v1
kind: Secret
metadata:
  name: large-secret
  namespace: default
type: Opaque
data:
  token: %s
---
apiVersion: v1
kind: Service
metadata:
  name: nginx-svc
  namespace: default
spec:
  ports:
    - port: 80
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: nginx
  namespace: default
spec:
  template:
    spec:
      containers:
        - name: nginx
          image: nginx:1.21
          securityContext:
            privileged: true
`, longSecretToken)

	// Test concurrent executions to verify exclusive workspace creation without collision
	const concurrency = 3
	errCh := make(chan error, concurrency)
	outCh := make(chan string, concurrency)

	for i := 0; i < concurrency; i++ {
		go func() {
			c := exec.Command("cmd.exe", "/c", batPath)
			c.Stdin = strings.NewReader(helmStdinInput)
			var outBuf, errBuf bytes.Buffer
			c.Stdout = &outBuf
			c.Stderr = &errBuf
			err := c.Run()
			if err != nil {
				errCh <- fmt.Errorf("concurrent run failed: %w (stderr: %s)", err, errBuf.String())
				return
			}
			outCh <- outBuf.String()
			errCh <- nil
		}()
	}

	for i := 0; i < concurrency; i++ {
		require.NoError(t, <-errCh)
		out := <-outCh
		assert.Contains(t, out, "privileged: false", "Kustomize patch must remediate privileged to false")
		assert.Contains(t, out, "nginx-svc", "Non-patched Service must pass through unmodified")
		assert.Contains(t, out, longSecretToken, "Long line (>8 KiB) in manifest must not be truncated or dropped by stdin streaming")
	}
}

// TestPostRenderer_NamespacelessHelmInputWithReleaseNamespace verifies that patches emitted
// with a non-default ReleaseNamespace apply via post-renderer to namespaceless Helm stdin manifests,
// without matching same-named resources in other namespaces.
func TestPostRenderer_NamespacelessHelmInputWithReleaseNamespace(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Skipping bash script execution test on Windows")
	}
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash executable not found in PATH")
	}
	if _, err := exec.LookPath("kustomize"); err != nil {
		t.Skip("kustomize executable not found in PATH")
	}

	kustDir := t.TempDir()
	outDir := filepath.Join(kustDir, "renderer")

	// Emit Kustomize patches for namespaceless Service with ReleaseNamespace: "prod"
	svc := &reporthandling.Resource{
		Object: map[string]interface{}{
			"apiVersion": "v1",
			"kind":       "Service",
			"metadata": map[string]interface{}{
				"name": "my-service",
			},
			"spec": map[string]interface{}{
				"type": "ClusterIP",
			},
		},
	}
	s := HelmFixSuggestion{
		Resource:           svc,
		FidelityProvenance: true,
		HelmValueOptions: cautils.HelmValueOptions{
			ReleaseNamespace: "prod",
		},
		FixPaths: []armotypes.FixPath{
			{Path: "metadata.labels.patched", Value: "applied"},
		},
	}

	emitRes, err := EmitKustomizePatch([]HelmFixSuggestion{s}, kustDir, WithOverwrite(true))
	require.NoError(t, err)
	require.Len(t, emitRes.EmittedResources, 1)

	err = EmitPostRenderer(kustDir, outDir)
	require.NoError(t, err)

	shPath := filepath.Join(outDir, "renderer.sh")
	require.FileExists(t, shPath)

	// Helm stdin input has:
	// 1. Service my-service without namespace (namespaceless Helm template)
	// 2. Service my-service in namespace other-ns
	helmStdinInput := `apiVersion: v1
kind: Service
metadata:
  name: my-service
spec:
  type: ClusterIP
---
apiVersion: v1
kind: Service
metadata:
  name: my-service
  namespace: other-ns
spec:
  type: ClusterIP
`

	cmd := exec.Command(shPath)
	cmd.Stdin = strings.NewReader(helmStdinInput)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err = cmd.Run()
	require.NoError(t, err, "post-renderer execution failed: %s", stderr.String())

	outStr := stdout.String()

	// Parse multi-document output
	decoder := yaml.NewDecoder(strings.NewReader(outStr))
	var docs []map[string]interface{}
	for {
		var doc map[string]interface{}
		if err := decoder.Decode(&doc); err != nil {
			break
		}
		if doc != nil {
			docs = append(docs, doc)
		}
	}
	require.Len(t, docs, 2, "expected two service documents in output")

	var namespaces []string
	for _, doc := range docs {
		meta, _ := doc["metadata"].(map[string]interface{})
		ns, _ := meta["namespace"].(string)
		namespaces = append(namespaces, ns)
	}
	assert.ElementsMatch(t, []string{"", "other-ns"}, namespaces, "output must contain one namespaceless and one other-ns Service")

	for _, doc := range docs {
		meta, ok := doc["metadata"].(map[string]interface{})
		require.True(t, ok)
		ns, _ := meta["namespace"].(string)
		labels, _ := meta["labels"].(map[string]interface{})
		switch ns {
		case "":
			// Namespaceless service (targeted by release namespace prod) MUST have the patch
			require.NotNil(t, labels, "namespaceless service should have labels")
			assert.Equal(t, "applied", labels["patched"], "namespaceless service must receive the patch")
		case "other-ns":
			// other-ns service MUST NOT have the patch
			if labels != nil {
				assert.Empty(t, labels["patched"], "other-ns service must NOT receive the patch")
			}
		}
	}

	// Verify that an explicit default-namespace Service also matches the selector alternative and receives the patch.
	// Note: Kustomize internally assigns default namespace to namespaceless resources,
	// so a namespaceless and explicit default resource with identical name cannot reside in the same stream.
	helmStdinDefaultNs := `apiVersion: v1
kind: Service
metadata:
  name: my-service
  namespace: default
spec:
  type: ClusterIP
---
apiVersion: v1
kind: Service
metadata:
  name: my-service
  namespace: other-ns
spec:
  type: ClusterIP
`
	cmdDefault := exec.Command(shPath)
	cmdDefault.Stdin = strings.NewReader(helmStdinDefaultNs)
	var stdoutDef, stderrDef bytes.Buffer
	cmdDefault.Stdout = &stdoutDef
	cmdDefault.Stderr = &stderrDef
	err = cmdDefault.Run()
	require.NoError(t, err, "post-renderer execution for default-ns failed: %s", stderrDef.String())

	decDefault := yaml.NewDecoder(strings.NewReader(stdoutDef.String()))
	var docsDefault []map[string]interface{}
	for {
		var doc map[string]interface{}
		if err := decDefault.Decode(&doc); err != nil {
			break
		}
		if doc != nil {
			docsDefault = append(docsDefault, doc)
		}
	}
	require.Len(t, docsDefault, 2, "expected two service documents in default-ns output")

	var namespacesDefault []string
	for _, doc := range docsDefault {
		meta, _ := doc["metadata"].(map[string]interface{})
		ns, _ := meta["namespace"].(string)
		namespacesDefault = append(namespacesDefault, ns)
	}
	assert.ElementsMatch(t, []string{"default", "other-ns"}, namespacesDefault, "default-ns output must contain one default and one other-ns Service")

	for _, doc := range docsDefault {
		meta, ok := doc["metadata"].(map[string]interface{})
		require.True(t, ok)
		ns, _ := meta["namespace"].(string)
		labels, _ := meta["labels"].(map[string]interface{})
		switch ns {
		case "default":
			require.NotNil(t, labels, "default-namespace service should have labels")
			assert.Equal(t, "applied", labels["patched"], "default-namespace service must receive the patch")
		case "other-ns":
			if labels != nil {
				assert.Empty(t, labels["patched"], "other-ns service must NOT receive the patch")
			}
		}
	}
}
