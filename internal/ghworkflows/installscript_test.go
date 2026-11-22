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
	homeDir := filepath.Join(tempDir, "home")

	if err := os.MkdirAll(homeDir, 0700); err != nil {
		t.Fatal(err)
	}

	// Simulate GitHub API rate limiting.
	bashEnv := filepath.Join(tempDir, "bash_env")
	bashEnvScript := `curl() {
    printf '%s\n' '{"message":"API rate limit exceeded"}'
}
`

	if err := os.WriteFile(bashEnv, []byte(bashEnvScript), 0600); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command("bash", installScript)

	cmd.Env = replaceEnvValueForInstallTest(
		os.Environ(),
		"BASH_ENV",
		bashEnv,
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
	// Verify that the installer resets terminal colors when it exits.
	if !strings.HasSuffix(stdout.String(), "\x1b[0m") {
		t.Errorf("expected installer output to end with terminal reset sequence, got: %q", stdout.String())
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
