package core

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/project-copacetic/copacetic/pkg/buildkit"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildPatchExportOCI(t *testing.T) {
	t.Run("requires output path", func(t *testing.T) {
		_, _, err := buildPatchExport("oci", "", "example.test/app:patched")
		require.ErrorContains(t, err, "output-path must be provided")
	})

	t.Run("creates parent directories and output file", func(t *testing.T) {
		outputPath := filepath.Join(t.TempDir(), "nested", "patched.tar")
		entry, pipeReader, err := buildPatchExport("oci", outputPath, "example.test/app:patched")
		require.NoError(t, err)
		assert.Nil(t, pipeReader)
		assert.Equal(t, "oci", entry.Type)
		assert.Equal(t, "example.test/app:patched", entry.Attrs["name"])

		writer, err := entry.Output(nil)
		require.NoError(t, err)
		_, err = writer.Write([]byte("image archive"))
		require.NoError(t, err)
		require.NoError(t, writer.Close())

		contents, err := os.ReadFile(outputPath)
		require.NoError(t, err)
		assert.Equal(t, []byte("image archive"), contents)
	})
}

func TestBuildPatchExportLocal(t *testing.T) {
	_, _, err := buildPatchExport("local", "", "example.test/app:patched")
	require.ErrorContains(t, err, "output-path must be provided")

	outputPath := filepath.Join(t.TempDir(), "rootfs")
	entry, pipeReader, err := buildPatchExport("local", outputPath, "example.test/app:patched")
	require.NoError(t, err)
	assert.Nil(t, pipeReader)
	assert.Equal(t, "local", entry.Type)
	assert.Equal(t, outputPath, entry.OutputDir)
}

func TestDockerLoad(t *testing.T) {
	tests := []struct {
		name       string
		scriptBody string
		wantError  string
	}{
		{name: "success", scriptBody: "#!/bin/sh\ncat >/dev/null\n"},
		{name: "failure includes command output", scriptBody: "#!/bin/sh\ncat >/dev/null\necho load-rejected >&2\nexit 7\n", wantError: "load-rejected"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			binDir := t.TempDir()
			dockerPath := filepath.Join(binDir, "docker")
			require.NoError(t, os.WriteFile(dockerPath, []byte(test.scriptBody), 0o600))
			require.NoError(t, os.Chmod(dockerPath, 0o700))
			t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))

			err := dockerLoad(context.Background(), bytes.NewBufferString("image archive"))
			if test.wantError == "" {
				require.NoError(t, err)
				return
			}
			require.ErrorContains(t, err, "docker load failed")
			assert.ErrorContains(t, err, test.wantError)
		})
	}
}

func TestTryParseScanReport(t *testing.T) {
	report := `{
		"matches": [{
			"vulnerability": {"id": "CVE-2026-0001", "fix": {"state": "fixed", "versions": ["3.0.1"]}},
			"artifact": {"name": "openssl", "version": "3.0.0", "language": ""}
		}],
		"source": {"target": {"architecture": "amd64"}},
		"distro": {"name": "ubuntu", "version": "24.04"},
		"descriptor": {"name": "grype"}
	}`
	path := filepath.Join(t.TempDir(), "grype.json")
	require.NoError(t, os.WriteFile(path, []byte(report), 0o600))

	manifest, err := tryParseScanReport(path)
	require.NoError(t, err)
	assert.Equal(t, "ubuntu", manifest.Metadata.OS.Type)
	assert.Equal(t, "24.04", manifest.Metadata.OS.Version)
	assert.Equal(t, "amd64", manifest.Metadata.Config.Arch)
	require.Len(t, manifest.Updates, 1)
	assert.Equal(t, "openssl", manifest.Updates[0].Name)
	assert.Equal(t, "3.0.0", manifest.Updates[0].InstalledVersion)
	assert.Equal(t, "3.0.1", manifest.Updates[0].FixedVersion)
	assert.Equal(t, "CVE-2026-0001", manifest.Updates[0].VulnerabilityID)
}

// TestResolveBuildkitOpts guards against a regression where bkOpts.Addr was
// never populated from the --address flag, so buildkit.NewClient always saw
// an empty Addr and silently ignored the endpoint the user asked for.
func TestResolveBuildkitOpts(t *testing.T) {
	t.Run("fills Addr from buildkitAddr when unset", func(t *testing.T) {
		got := resolveBuildkitOpts("tcp://remote-buildkit:1234", buildkit.Opts{})
		assert.Equal(t, "tcp://remote-buildkit:1234", got.Addr)
	})

	t.Run("empty buildkitAddr (the flag's default) leaves Addr empty for auto-detection", func(t *testing.T) {
		got := resolveBuildkitOpts("", buildkit.Opts{})
		assert.Equal(t, "", got.Addr)
	})

	t.Run("does not override an already-set Addr", func(t *testing.T) {
		got := resolveBuildkitOpts("tcp://remote-buildkit:1234", buildkit.Opts{Addr: "tcp://explicit:5678"})
		assert.Equal(t, "tcp://explicit:5678", got.Addr)
	})

	t.Run("other bkOpts fields are preserved", func(t *testing.T) {
		got := resolveBuildkitOpts("tcp://remote-buildkit:1234", buildkit.Opts{
			CACertPath: "/ca.pem",
			CertPath:   "/cert.pem",
			KeyPath:    "/key.pem",
		})
		assert.Equal(t, "tcp://remote-buildkit:1234", got.Addr)
		assert.Equal(t, "/ca.pem", got.CACertPath)
		assert.Equal(t, "/cert.pem", got.CertPath)
		assert.Equal(t, "/key.pem", got.KeyPath)
	})
}

func TestPatchWithContextRejectsInvalidReport(t *testing.T) {
	reportPath := filepath.Join(t.TempDir(), "invalid.json")
	require.NoError(t, os.WriteFile(reportPath, []byte("not-json"), 0o600))

	err := patchWithContext(
		context.Background(),
		"unused-buildkit-address",
		"nginx:latest",
		reportPath,
		"nginx:patched",
		filepath.Join(t.TempDir(), "working"),
		false,
		"image",
		"",
		buildkit.Opts{},
	)
	require.ErrorContains(t, err, "invalid character")
}

func TestCopaPatchReturnsEarlyErrors(t *testing.T) {
	reportPath := filepath.Join(t.TempDir(), "invalid.json")
	require.NoError(t, os.WriteFile(reportPath, []byte("not-json"), 0o600))

	err := copaPatch(
		context.Background(),
		5*time.Second,
		"unused-buildkit-address",
		"nginx:latest",
		reportPath,
		"nginx:patched",
		filepath.Join(t.TempDir(), "working"),
		false,
		"image",
		"",
		buildkit.Opts{},
	)
	require.ErrorContains(t, err, "invalid character")
}
