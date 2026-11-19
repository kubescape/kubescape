package ghworkflows

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/kubescape/kubescape/v4/internal/testutils"
)

func TestInstallScriptReportsLatestVersionLookupFailure(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("install.sh requires bash")
	}

	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash is required")
	}

	repoRoot := filepath.Clean(filepath.Join(testutils.CurrentDir(), "..", ".."))
	installScript := filepath.Join(repoRoot, "install.sh")

	tempDir := t.TempDir()
	fakeBin := filepath.Join(tempDir, "bin")
	homeDir := filepath.Join(tempDir, "home")

	for _, dir := range []string{fakeBin, homeDir} {
		if err := os.MkdirAll(dir, 0755); err != nil {
			t.Fatal(err)
		}
	}

	// Simulate GitHub API rate limiting.
	fakeCurl := filepath.Join(fakeBin, "curl")
	curlScript := `#!/bin/sh
printf '%s\n' '{"message":"API rate limit exceeded"}'
`

	if err := os.WriteFile(fakeCurl, []byte(curlScript), 0755); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command("bash", installScript)

	cmd.Env = replaceEnvValueForInstallTest(
		os.Environ(),
		"PATH",
		fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"),
	)
	cmd.Env = replaceEnvValueForInstallTest(cmd.Env, "HOME", homeDir)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err == nil {
		t.Fatal("expected installer to fail when latest version lookup fails")
	}

	exitErr, ok := err.(*exec.ExitError)
	if !ok || exitErr.ExitCode() != 1 {
		t.Fatalf("expected exit code 1, got %v", err)
	}

	if !strings.Contains(stderr.String(), "Failed to fetch latest release version") {
		t.Errorf("expected error on stderr, got:\nstderr: %s\nstdout: %s",
			stderr.String(), stdout.String())
	}

	if !strings.Contains(stderr.String(), "specific version") {
		t.Errorf("expected a specific-version installation hint on stderr, got: %s",
			stderr.String())
	}

	if strings.Contains(stdout.String(), "Failed to fetch latest release version") {
		t.Errorf("error should not be printed to stdout: %s", stdout.String())
	}

	if _, err := os.Stat(filepath.Join(homeDir, ".kubescape")); !os.IsNotExist(err) {
		t.Errorf("expected no installation directory, stat error: %v", err)
	}
}

func replaceEnvValueForInstallTest(env []string, key, value string) []string {
	prefix := key + "="

	for i, entry := range env {
		if strings.HasPrefix(entry, prefix) {
			env[i] = prefix + value
			return env
		}
	}

	return append(env, prefix+value)
}
