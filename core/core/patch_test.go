package core

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/moby/buildkit/client"
	"github.com/project-copacetic/copacetic/pkg/types/unversioned"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSanitizeImageRefForFilename pins the cross-platform filename guarantee:
// image references legally contain ':', '/', '@' and whitespace, all of which
// are illegal or hazardous in filenames on at least one supported OS. It also
// verifies filesystem-reserved characters (*, \, ?, <, >, |, ") are replaced.
func TestSanitizeImageRefForFilename(t *testing.T) {
	tests := []struct {
		name  string
		image string
		want  string
	}{
		{name: "tagged image", image: "nginx:1.22", want: "nginx-1.22"},
		{name: "name-only image", image: "nginx", want: "nginx"},
		{name: "repository path", image: "myrepo/myapp:2.0", want: "myrepo-myapp-2.0"},
		{name: "registry with port", image: "registry.example.com:8443/myapp:3.1", want: "registry.example.com-8443-myapp-3.1"},
		{name: "digest-pinned reference", image: "myrepo/myapp@sha256:9f86d081", want: "myrepo-myapp-sha256-9f86d081"},
		{name: "surrounding whitespace trimmed", image: "  nginx:1.22  ", want: "nginx-1.22"},
		{name: "wildcard and backslash sanitized", image: `my*repo\app:1.0`, want: "my-repo-app-1.0"},
		{name: "windows reserved characters sanitized", image: `app<?>|"*:v1`, want: "app-------v1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sanitizeImageRefForFilename(tt.image)
			assert.Equal(t, tt.want, got)
			assert.NotContains(t, got, ":")
			assert.NotContains(t, got, "/")
			assert.NotContains(t, got, "@")
			assert.NotContains(t, got, "*")
			assert.NotContains(t, got, "\\")
			assert.NotContains(t, got, "?")
			assert.NotContains(t, got, "<")
			assert.NotContains(t, got, ">")
			assert.NotContains(t, got, "|")
			assert.NotContains(t, got, "\"")
		})
	}
}

// TestUpdatesCountToleratesUpdateAllMode guards the update-all path: with no
// scanner report there are no updates, and reading len on a nil value must
// never panic.
func TestUpdatesCountToleratesUpdateAllMode(t *testing.T) {
	assert.Equal(t, 0, updatesCount(nil))
	assert.Equal(t, 0, updatesCount(&unversioned.UpdateManifest{}))
	assert.Equal(t, 2, updatesCount(&unversioned.UpdateManifest{
		OSUpdates: unversioned.UpdatePackages{{}, {}},
	}))
	assert.Equal(t, 2, updatesCount(&unversioned.UpdateManifest{
		LangUpdates: unversioned.LangUpdatePackages{{}, {}},
	}))
	assert.Equal(t, 3, updatesCount(&unversioned.UpdateManifest{
		OSUpdates:   unversioned.UpdatePackages{{}},
		LangUpdates: unversioned.LangUpdatePackages{{}, {}},
	}))
}

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

// TestPatchIntermediateFileCleanup verifies that intermediate scan files
// created for copacetic via createIntermediateScanFile are closed and deleted via
// deferred cleanup on both error and success paths.
func TestPatchIntermediateFileCleanup(t *testing.T) {
	cleanupFn := func(simulateFailure bool) error {
		f, createErr := createIntermediateScanFile("test-image:1.0")
		if createErr != nil {
			return createErr
		}
		fileName := f.Name()
		defer func() {
			if remErr := os.Remove(fileName); remErr != nil && !errors.Is(remErr, os.ErrNotExist) {
				t.Errorf("failed to remove intermediate file: %v", remErr)
			}
		}()

		_, writeErr := f.WriteString("{\"test\": \"data\"}")
		require.NoError(t, writeErr)
		require.NoError(t, f.Close(), "file must close without error before downstream reading/cleanup")

		if simulateFailure {
			return errors.New("simulated downstream copa failure")
		}
		return nil
	}

	t.Run("cleanup on success", func(t *testing.T) {
		err := cleanupFn(false)
		assert.NoError(t, err)
	})

	t.Run("cleanup on error", func(t *testing.T) {
		err := cleanupFn(true)
		assert.Error(t, err)
	})
}

// TestCreateIntermediateScanFile_LocationAndPermissions verifies that intermediate scan files
// are created in the OS temporary directory with secure 0600 permissions.
func TestCreateIntermediateScanFile_LocationAndPermissions(t *testing.T) {
	f, err := createIntermediateScanFile("nginx:1.22")
	require.NoError(t, err)
	path := f.Name()
	defer func() { _ = os.Remove(path) }()
	require.NoError(t, f.Close())

	// Ensure the file is inside the OS temp directory
	tempDir := os.TempDir()
	rel, err := filepath.Rel(tempDir, path)
	require.NoError(t, err)
	assert.False(t, strings.HasPrefix(rel, ".."), "file %q must reside inside temp dir %q", path, tempDir)

	// Ensure prefix and suffix
	base := filepath.Base(path)
	assert.True(t, strings.HasPrefix(base, "kubescape-patch-nginx-1.22-"), "expected prefix in %q", base)
	assert.True(t, strings.HasSuffix(base, ".json"), "expected .json suffix in %q", base)

	// Verify permissions are 0600 (owner read-write only)
	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm(), "file permissions must be 0600")
}

// TestCreateIntermediateScanFile_LeavesUserWorkingDirectoryUntouched guards against
// data loss: existing files in the current working directory must never be truncated,
// overwritten, or deleted by intermediate patch file creation and cleanup.
func TestCreateIntermediateScanFile_LeavesUserWorkingDirectoryUntouched(t *testing.T) {
	tmpDir := t.TempDir()
	origWD, err := os.Getwd()
	require.NoError(t, err)
	require.NoError(t, os.Chdir(tmpDir))
	t.Cleanup(func() { _ = os.Chdir(origWD) })

	// Pre-create user files in the working directory that would have collided under
	// the legacy scheme (e.g. nginx-1.22.json).
	userContent := []byte(`{"important_user_manifest": true}`)
	legacyName := fmt.Sprintf("%s.json", sanitizeImageRefForFilename("nginx:1.22"))
	require.NoError(t, os.WriteFile(legacyName, userContent, 0o644))

	// Also create a file matching the new temp pattern prefix in cwd to be extra thorough
	cwdPatternFile := "kubescape-patch-nginx-1.22-local.json"
	require.NoError(t, os.WriteFile(cwdPatternFile, userContent, 0o644))

	// Create and clean up the intermediate scan file
	f, err := createIntermediateScanFile("nginx:1.22")
	require.NoError(t, err)
	path := f.Name()
	_, err = f.WriteString(`{"scan": "intermediate"}`)
	require.NoError(t, err)
	require.NoError(t, f.Close())

	// Simulate cleanup
	require.NoError(t, os.Remove(path))

	// Verify pre-existing user files in cwd are completely intact and untouched
	gotLegacy, err := os.ReadFile(legacyName)
	require.NoError(t, err, "pre-existing cwd file must not be deleted")
	assert.Equal(t, userContent, gotLegacy, "pre-existing cwd file content must not be modified or truncated")

	gotPattern, err := os.ReadFile(cwdPatternFile)
	require.NoError(t, err, "cwd file matching pattern prefix must not be deleted")
	assert.Equal(t, userContent, gotPattern, "cwd file content must not be modified or truncated")
}

// TestCreateIntermediateScanFile_WorksInReadOnlyWorkingDirectory verifies that
// patch intermediate file creation succeeds even if the current working directory is read-only.
func TestCreateIntermediateScanFile_WorksInReadOnlyWorkingDirectory(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("skipping read-only directory test when running as root")
	}

	tmpDir := t.TempDir()
	roDir := filepath.Join(tmpDir, "readonly")
	require.NoError(t, os.Mkdir(roDir, 0o755))

	origWD, err := os.Getwd()
	require.NoError(t, err)
	require.NoError(t, os.Chdir(roDir))
	t.Cleanup(func() {
		_ = os.Chmod(roDir, 0o755)
		_ = os.Chdir(origWD)
	})

	// Make the directory read-only
	require.NoError(t, os.Chmod(roDir, 0o555))

	// Confirm writing to cwd fails
	_, err = os.Create("test.txt")
	require.Error(t, err, "creating file in read-only directory must fail")

	// Creating intermediate file must succeed because it uses os.TempDir()
	f, err := createIntermediateScanFile("nginx:1.22")
	require.NoError(t, err, "createIntermediateScanFile must succeed even when cwd is read-only")
	path := f.Name()
	defer func() { _ = os.Remove(path) }()
	require.NoError(t, f.Close())
}

// TestCreateIntermediateScanFile_ConcurrentInvocations verifies that parallel
// invocations create unique files without race conditions or collisions.
func TestCreateIntermediateScanFile_ConcurrentInvocations(t *testing.T) {
	const count = 20
	var wg sync.WaitGroup
	files := make([]string, count)
	errs := make([]error, count)

	for i := 0; i < count; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			f, err := createIntermediateScanFile("nginx:1.22")
			if err != nil {
				errs[idx] = err
				return
			}
			files[idx] = f.Name()
			_, _ = f.WriteString(fmt.Sprintf(`{"worker": %d}`, idx))
			_ = f.Close()
		}(i)
	}
	wg.Wait()

	seen := make(map[string]bool)
	for i := 0; i < count; i++ {
		require.NoError(t, errs[i], "worker %d failed to create intermediate file", i)
		assert.False(t, seen[files[i]], "duplicate file created across concurrent workers: %q", files[i])
		seen[files[i]] = true
		_ = os.Remove(files[i])
	}
}

// TestCreateIntermediateScanFile_LongImageRef verifies that long image references
// do not exceed filesystem filename limits.
func TestCreateIntermediateScanFile_LongImageRef(t *testing.T) {
	longImage := "registry.example.com:5000/very/deep/repository/path/with/lots/of/subnamespaces/and/components/my-service:" + strings.Repeat("a", 150)
	f, err := createIntermediateScanFile(longImage)
	require.NoError(t, err)
	defer func() { _ = os.Remove(f.Name()) }()
	require.NoError(t, f.Close())
}
