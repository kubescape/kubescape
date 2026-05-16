package core

import (
	"context"
	"errors"
	"os/exec"
	"testing"

	"github.com/moby/buildkit/client"
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
	entry, pipeR, err := buildPatchExport(true, "docker.io/library/nginx:1.23-patched")

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

	entry, pipeR, err := buildPatchExport(false, "docker.io/library/nginx:1.23-patched")

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

	_, _, err := buildPatchExport(false, "nginx:1.23-patched")

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
