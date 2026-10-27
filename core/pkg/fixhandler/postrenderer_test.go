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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

	// Verify batch script escaped % to %%
	batPath := filepath.Join(outDir, "renderer.bat")
	batData, err := os.ReadFile(batPath)
	require.NoError(t, err)
	assert.Contains(t, string(batData), "%%", "batch script must escape % as %%")

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

	cmd := exec.Command(shPath)
	cmd.Stdin = strings.NewReader("apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: test\n")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	runErr := cmd.Run()
	require.Error(t, runErr, "renderer.sh must exit with error when kustomization.yaml is missing")
	assert.Contains(t, stderr.String(), "refusing to emit unpatched manifests")
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

	cmd := exec.Command("cmd.exe", "/c", batPath)
	cmd.Stdin = strings.NewReader(helmStdinInput)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	runErr := cmd.Run()
	require.NoError(t, runErr, "renderer.bat execution failed: %s", stderr.String())

	output := stdout.String()
	assert.Contains(t, output, "privileged: false", "Kustomize patch must remediate privileged to false")
	assert.Contains(t, output, "nginx-svc", "Non-patched Service must pass through unmodified")
}
