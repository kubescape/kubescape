package core

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"testing"

	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/moby/buildkit/client"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestBuildPatchedImageName guards the fix for kubescape/kubescape#2189: the
// patched image must be exported under its canonical reference so containerd
// registers it under docker.io/library/... and docker/grype can resolve it
// locally.
func TestBuildPatchedImageName(t *testing.T) {
	tests := []struct {
		name       string
		image      string
		patchedTag string
		expected   string
		wantErr    bool
	}{
		{
			name:       "official docker hub image expands to docker.io/library",
			image:      "nginx:1.23",
			patchedTag: "1.23-patched",
			expected:   "docker.io/library/nginx:1.23-patched",
		},
		{
			name:       "fully qualified official image",
			image:      "docker.io/library/nginx:1.23",
			patchedTag: "1.23-patched",
			expected:   "docker.io/library/nginx:1.23-patched",
		},
		{
			name:       "docker hub user image",
			image:      "myuser/myapp:v1",
			patchedTag: "v1-patched",
			expected:   "docker.io/myuser/myapp:v1-patched",
		},
		{
			name:       "private registry image preserves host",
			image:      "quay.io/foo/bar:1.0",
			patchedTag: "1.0-patched",
			expected:   "quay.io/foo/bar:1.0-patched",
		},
		{
			name:    "invalid reference returns error",
			image:   "Invalid Image!!",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := buildPatchedImageName(tt.image, tt.patchedTag)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tt.expected, got)
		})
	}
}

// TestBuildPatchExport_PushTrue verifies that --push routes through
// ExporterImage with the buildkit "push" attribute set. Without that attr
// nothing reaches the source registry.
func TestBuildPatchExport_PushTrue(t *testing.T) {
	entry, pipeR, err := buildPatchExport("image", "", "docker.io/library/nginx:1.23-patched")

	require.NoError(t, err)
	assert.Nil(t, pipeR, "pipe reader must be unused in push mode")
	assert.Equal(t, client.ExporterImage, entry.Type)
	assert.Equal(t, "docker.io/library/nginx:1.23-patched", entry.Attrs["name"])
	assert.Equal(t, "true", entry.Attrs["push"],
		`push=true must set Attrs["push"]="true" — otherwise the image is built but never uploaded`)
	assert.Nil(t, entry.Output, "ExporterImage path must not register an Output sink")
}

// TestBuildPatchExport_PushFalse is the regression guard for the blocker on
// kubescape/kubescape#2199: the original implementation used ExporterImage
// for the no-push case, which only lands in dockerd's image store when
// buildkit and dockerd happen to share a containerd store. The supported
// behavior is ExporterDocker piped through `docker load`. See:
// https://github.com/moby/buildkit?tab=readme-ov-file#containerd-image-store
func TestBuildPatchExport_PushFalse(t *testing.T) {
	origLookPath := lookPath
	lookPath = func(file string) (string, error) {
		assert.Equal(t, "docker", file, "preflight must look up the docker CLI specifically")
		return "/usr/bin/docker", nil
	}
	t.Cleanup(func() { lookPath = origLookPath })

	entry, pipeR, err := buildPatchExport("docker", "", "docker.io/library/nginx:1.23-patched")

	require.NoError(t, err)
	require.NotNil(t, pipeR, "no-push path must hand back a pipe reader for docker load")
	assert.Equal(t, client.ExporterDocker, entry.Type,
		"no-push must use ExporterDocker (docker load) — ExporterImage does not guarantee a local-load")
	assert.Equal(t, "docker.io/library/nginx:1.23-patched", entry.Attrs["name"])
	_, hasPush := entry.Attrs["push"]
	assert.False(t, hasPush, `Attrs["push"] must NOT be set in the no-push path`)
	require.NotNil(t, entry.Output, "ExporterDocker must register an Output sink to receive the tarball")

	// The Output callback wires buildkit's tarball into the pipe that dockerLoad
	// reads from; sanity-check that the writer end is live so a real build wouldn't
	// fail at the first byte.
	w, err := entry.Output(nil)
	require.NoError(t, err)
	require.NotNil(t, w)
	require.NoError(t, w.Close())
}

// TestBuildPatchExport_PushFalseDockerMissing verifies the preflight fails
// fast with an actionable message rather than letting buildkit run to
// completion and then dumping the tarball into a /dev/null reader.
func TestBuildPatchExport_PushFalseDockerMissing(t *testing.T) {
	origLookPath := lookPath
	lookPath = func(string) (string, error) { return "", exec.ErrNotFound }
	t.Cleanup(func() { lookPath = origLookPath })

	_, _, err := buildPatchExport("docker", "", "nginx:1.23-patched")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "docker CLI",
		"error must name the missing dependency so users know what to install")
	assert.Contains(t, err.Error(), "--push",
		"error must point users at --push as the workaround")
}

func TestGetOSType(t *testing.T) {
	tests := []struct {
		name          string
		osRelease     string
		expected      string
		expectedError error
		wantError     bool
	}{
		{
			name: "alpine",
			osRelease: `NAME="Alpine Linux"
VERSION_ID=3.19.1
`,
			expected: "alpine",
		},
		{
			name: "debian",
			osRelease: `NAME="Debian GNU/Linux"
VERSION_ID="12"
`,
			expected: "debian",
		},
		{
			name: "ubuntu",
			osRelease: `NAME="Ubuntu"
VERSION_ID="22.04"
`,
			expected: "ubuntu",
		},
		{
			name: "amazon linux",
			osRelease: `NAME="Amazon Linux"
VERSION_ID="2023"
`,
			expected: "amazon",
		},
		{
			name: "centos",
			osRelease: `NAME="CentOS Linux"
VERSION_ID="7"
`,
			expected: "centos",
		},
		{
			name: "mariner",
			osRelease: `NAME="CBL-Mariner"
VERSION_ID="2.0"
`,
			expected: "cbl-mariner",
		},
		{
			name: "azure linux",
			osRelease: `NAME="Azure Linux"
VERSION_ID="3.0"
`,
			expected: "azurelinux",
		},
		{
			name: "red hat",
			osRelease: `NAME="Red Hat Enterprise Linux"
VERSION_ID="9.4"
`,
			expected: "redhat",
		},
		{
			name: "rocky",
			osRelease: `NAME="Rocky Linux"
VERSION_ID="9.4"
`,
			expected: "rocky",
		},
		{
			name: "oracle",
			osRelease: `NAME="Oracle Linux Server"
VERSION_ID="8.9"
`,
			expected: "oracle",
		},
		{
			name: "alma",
			osRelease: `NAME="AlmaLinux"
VERSION_ID="9.4"
`,
			expected: "alma",
		},
		{
			name: "unsupported distro",
			osRelease: `NAME="Wolfi"
VERSION_ID="20240513"
`,
			expectedError: errors.ErrUnsupported,
		},
		{
			name:      "malformed os release",
			osRelease: "\x00",
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual, err := getOSType(context.Background(), []byte(tt.osRelease))

			if tt.expectedError != nil {
				assert.ErrorIs(t, err, tt.expectedError)
				assert.Empty(t, actual)
				return
			}
			if tt.wantError {
				assert.Error(t, err)
				assert.Empty(t, actual)
				return
			}

			assert.NoError(t, err)
			assert.Equal(t, tt.expected, actual)
		})
	}
}

func TestGetOSVersion(t *testing.T) {
	tests := []struct {
		name      string
		osRelease string
		expected  string
	}{
		{
			name: "quoted version",
			osRelease: `NAME="Ubuntu"
VERSION_ID="22.04"
`,
			expected: "22.04",
		},
		{
			name: "unquoted version",
			osRelease: `NAME="Amazon Linux"
VERSION_ID=2023
`,
			expected: "2023",
		},
		{
			name: "missing version",
			osRelease: `NAME="Debian GNU/Linux"
`,
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual, err := getOSVersion(context.Background(), []byte(tt.osRelease))

			assert.NoError(t, err)
			assert.Equal(t, tt.expected, actual)
		})
	}
}

// TestRunWithCopaLoggerMuted guards against a regression where Patch() left
// os.Stdout/os.Stderr nil through the printer setup that follows copaPatch().
// GetUIPrinter calls os.Stdout.Name(), which has no nil-receiver guard and
// panics, so runWithCopaLoggerMuted must restore the streams before it
// returns, on both the success and error paths.
func TestRunWithCopaLoggerMuted(t *testing.T) {
	sout, serr := os.Stdout, os.Stderr
	defer func() { os.Stdout, os.Stderr = sout, serr }()

	t.Run("success", func(t *testing.T) {
		err := runWithCopaLoggerMuted(false, func() error { return nil })
		require.NoError(t, err)
		require.NotNil(t, os.Stdout)
		require.NotNil(t, os.Stderr)

		scanInfo := &cautils.ScanInfo{}
		scanInfo.SetScanType(cautils.ScanTypeImage)
		assert.NotPanics(t, func() {
			_ = GetUIPrinter(context.Background(), scanInfo, "")
		})
	})

	t.Run("error", func(t *testing.T) {
		wantErr := errors.New("install failed")
		err := runWithCopaLoggerMuted(false, func() error { return wantErr })
		require.ErrorIs(t, err, wantErr)
		require.NotNil(t, os.Stdout)
		require.NotNil(t, os.Stderr)
	})

	t.Run("debug bypasses muting", func(t *testing.T) {
		err := runWithCopaLoggerMuted(true, func() error { return nil })
		require.NoError(t, err)
		require.NotNil(t, os.Stdout)
		require.NotNil(t, os.Stderr)
	})
}

// TestRunWithCopaLoggerMuted_RestoresActualPriorLogrusWriter guards against a
// regression where the logrus writer was restored to a value assumed to
// equal os.Stderr, rather than to whatever logrus was actually configured
// with beforehand. If something in the process had pointed logrus at a file,
// buffer, or hook writer before Patch() ran, that destination would be
// silently replaced with os.Stderr after a single "kubescape patch" call.
func TestRunWithCopaLoggerMuted_RestoresActualPriorLogrusWriter(t *testing.T) {
	prevOut := log.StandardLogger().Out
	t.Cleanup(func() { log.SetOutput(prevOut) })

	var customWriter bytes.Buffer
	log.SetOutput(&customWriter)

	var duringCallWriter io.Writer
	err := runWithCopaLoggerMuted(false, func() error {
		duringCallWriter = log.StandardLogger().Out
		log.Error("this must not reach customWriter or os.Stderr")
		return nil
	})
	require.NoError(t, err)

	assert.Equal(t, io.Discard, duringCallWriter, "logrus output must be discarded while fn runs")
	assert.Empty(t, customWriter.String(), "logrus output during fn must not leak to the pre-existing writer")
	assert.Same(t, &customWriter, log.StandardLogger().Out, "logrus writer must be restored to what it actually was, not assumed to be os.Stderr")
}
