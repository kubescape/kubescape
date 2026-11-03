package pathcontainment

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func skipOnWindowsSymlink(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		probe := filepath.Join(t.TempDir(), "probe")
		if err := os.Symlink(t.TempDir(), probe); err != nil {
			t.Skip("symlink tests require SeCreateSymbolicLinkPrivilege on Windows")
		}
	}
}

func TestResolveContainedPath_TableDriven(t *testing.T) {
	base := t.TempDir()

	// Setup directory structure inside base
	manifestsDir := filepath.Join(base, "manifests")
	require.NoError(t, os.Mkdir(manifestsDir, 0o750))
	validFile := filepath.Join(manifestsDir, "deploy.yaml")
	require.NoError(t, os.WriteFile(validFile, []byte("kind: Deployment"), 0o600))

	// External directory
	outside := t.TempDir()
	outsideFile := filepath.Join(outside, "secret.yaml")
	require.NoError(t, os.WriteFile(outsideFile, []byte("kind: Secret"), 0o600))

	tests := []struct {
		name          string
		baseDir       string
		target        string
		expectErr     bool
		expectedErrIs error
		checkResolved func(t *testing.T, res string)
	}{
		{
			name:      "unconstrained mode when baseDir is empty",
			baseDir:   "",
			target:    "manifests/deploy.yaml",
			expectErr: false,
			checkResolved: func(t *testing.T, res string) {
				assert.Equal(t, filepath.Clean("manifests/deploy.yaml"), res)
			},
		},
		{
			name:          "empty target returns ErrInvalidPath",
			baseDir:       base,
			target:        "",
			expectErr:     true,
			expectedErrIs: ErrInvalidPath,
		},
		{
			name:          "NUL byte in target returns ErrInvalidPath",
			baseDir:       base,
			target:        "manifests/deploy\x00.yaml",
			expectErr:     true,
			expectedErrIs: ErrInvalidPath,
		},
		{
			name:          "NUL byte in baseDir returns ErrInvalidPath",
			baseDir:       base + "\x00",
			target:        "manifests/deploy.yaml",
			expectErr:     true,
			expectedErrIs: ErrInvalidPath,
		},
		{
			name:      "exact base directory with dot",
			baseDir:   base,
			target:    ".",
			expectErr: false,
			checkResolved: func(t *testing.T, res string) {
				canonBase, err := filepath.EvalSymlinks(base)
				require.NoError(t, err)
				assert.Equal(t, canonBase, res)
			},
		},
		{
			name:      "exact base directory with absolute path",
			baseDir:   base,
			target:    base,
			expectErr: false,
			checkResolved: func(t *testing.T, res string) {
				canonBase, err := filepath.EvalSymlinks(base)
				require.NoError(t, err)
				assert.Equal(t, canonBase, res)
			},
		},
		{
			name:      "valid relative subpath",
			baseDir:   base,
			target:    "manifests/deploy.yaml",
			expectErr: false,
			checkResolved: func(t *testing.T, res string) {
				canonValid, err := filepath.EvalSymlinks(validFile)
				require.NoError(t, err)
				assert.Equal(t, canonValid, res)
			},
		},
		{
			name:      "valid missing tail subpath",
			baseDir:   base,
			target:    "manifests/new-service.yaml",
			expectErr: false,
			checkResolved: func(t *testing.T, res string) {
				canonManifests, err := filepath.EvalSymlinks(manifestsDir)
				require.NoError(t, err)
				assert.Equal(t, filepath.Join(canonManifests, "new-service.yaml"), res)
			},
		},
		{
			name:      "valid multi-level missing tail subpath",
			baseDir:   base,
			target:    "manifests/nested/new/service.yaml",
			expectErr: false,
			checkResolved: func(t *testing.T, res string) {
				canonManifests, err := filepath.EvalSymlinks(manifestsDir)
				require.NoError(t, err)
				assert.Equal(t, filepath.Join(canonManifests, "nested", "new", "service.yaml"), res)
			},
		},
		{
			name:          "directory traversal with parent references escapes workspace",
			baseDir:       base,
			target:        "../../etc/shadow",
			expectErr:     true,
			expectedErrIs: ErrPathEscapesWorkspace,
		},
		{
			name:          "missing component followed by parent references escapes workspace",
			baseDir:       base,
			target:        "manifests/nested/../../../../outside.yaml",
			expectErr:     true,
			expectedErrIs: ErrPathEscapesWorkspace,
		},
		{
			name:          "parent traversal on regular file returns ErrInvalidPath",
			baseDir:       base,
			target:        "manifests/deploy.yaml/../other.yaml",
			expectErr:     true,
			expectedErrIs: ErrInvalidPath,
		},
		{
			name:          "absolute path outside workspace escapes workspace",
			baseDir:       base,
			target:        outsideFile,
			expectErr:     true,
			expectedErrIs: ErrPathEscapesWorkspace,
		},
		{
			name:      "non-existent baseDir returns error",
			baseDir:   filepath.Join(base, "does-not-exist"),
			target:    "manifests/deploy.yaml",
			expectErr: true,
		},
		{
			name:      "file as baseDir returns error",
			baseDir:   validFile,
			target:    "deploy.yaml",
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resolved, err := ResolveContainedPath(tt.baseDir, tt.target)
			if tt.expectErr {
				require.Error(t, err)
				if tt.expectedErrIs != nil {
					assert.True(t, errors.Is(err, tt.expectedErrIs), "expected error to be %v, got %v", tt.expectedErrIs, err)
				}
			} else {
				require.NoError(t, err)
				if tt.checkResolved != nil {
					tt.checkResolved(t, resolved)
				}
			}
		})
	}
}

func TestResolveContainedPath_Symlinks(t *testing.T) {
	skipOnWindowsSymlink(t)

	base := t.TempDir()
	outside := t.TempDir()

	// 1. Symlink inside base pointing outside base
	outsideDir := filepath.Join(outside, "dir")
	require.NoError(t, os.Mkdir(outsideDir, 0o750))
	outsideTarget := filepath.Join(outsideDir, "victim.yaml")
	require.NoError(t, os.WriteFile(outsideTarget, []byte("sensitive data"), 0o600))
	outsideSecret := filepath.Join(outside, "secret.yaml")
	require.NoError(t, os.WriteFile(outsideSecret, []byte("super secret"), 0o600))

	outsideSymlink := filepath.Join(base, "symlink-outside")
	require.NoError(t, os.Symlink(outsideDir, outsideSymlink))

	t.Run("symlink inside base pointing outside is rejected", func(t *testing.T) {
		target := filepath.Join(outsideSymlink, "victim.yaml")
		_, err := ResolveContainedPath(base, target)
		require.Error(t, err)
		assert.True(t, errors.Is(err, ErrPathEscapesWorkspace), "expected ErrPathEscapesWorkspace, got %v", err)
	})

	t.Run("symlink inside base pointing outside with relative path is rejected", func(t *testing.T) {
		_, err := ResolveContainedPath(base, "symlink-outside/victim.yaml")
		require.Error(t, err)
		assert.True(t, errors.Is(err, ErrPathEscapesWorkspace), "expected ErrPathEscapesWorkspace, got %v", err)
	})

	// Regression cases for matthyx review: symlink/.. traversal
	t.Run("relative symlink parent traversal escaping workspace is rejected", func(t *testing.T) {
		// symlink-outside -> outside/dir, so symlink-outside/../secret.yaml
		// physically resolves to outside/secret.yaml.
		// Lexical clean would incorrectly collapse it to secret.yaml inside base.
		_, err := ResolveContainedPath(base, "symlink-outside/../secret.yaml")
		require.Error(t, err)
		assert.True(t, errors.Is(err, ErrPathEscapesWorkspace), "expected ErrPathEscapesWorkspace, got %v", err)
	})

	t.Run("absolute symlink parent traversal escaping workspace is rejected", func(t *testing.T) {
		absPath := filepath.Join(base, "symlink-outside") + string(filepath.Separator) + ".." + string(filepath.Separator) + "secret.yaml"
		_, err := ResolveContainedPath(base, absPath)
		require.Error(t, err)
		assert.True(t, errors.Is(err, ErrPathEscapesWorkspace), "expected ErrPathEscapesWorkspace, got %v", err)
	})

	t.Run("symlink parent traversal with missing tail escaping workspace is rejected", func(t *testing.T) {
		_, err := ResolveContainedPath(base, "symlink-outside/../missing.yaml")
		require.Error(t, err)
		assert.True(t, errors.Is(err, ErrPathEscapesWorkspace), "expected ErrPathEscapesWorkspace, got %v", err)
	})

	// 2. Symlink inside base pointing back inside base
	internalParent := filepath.Join(base, "internal")
	internalDir := filepath.Join(internalParent, "sub")
	require.NoError(t, os.MkdirAll(internalDir, 0o750))
	internalFile := filepath.Join(internalDir, "app.yaml")
	require.NoError(t, os.WriteFile(internalFile, []byte("kind: Pod"), 0o600))
	parentFile := filepath.Join(internalParent, "parent.yaml")
	require.NoError(t, os.WriteFile(parentFile, []byte("kind: Parent"), 0o600))

	insideSymlink := filepath.Join(base, "symlink-inside")
	require.NoError(t, os.Symlink(internalDir, insideSymlink))

	t.Run("symlink inside base pointing inside base is accepted", func(t *testing.T) {
		resolved, err := ResolveContainedPath(base, "symlink-inside/app.yaml")
		require.NoError(t, err)
		canonInternal, err := filepath.EvalSymlinks(internalFile)
		require.NoError(t, err)
		assert.Equal(t, canonInternal, resolved)
	})

	t.Run("internal symlink parent traversal resolves to physical parent manifest", func(t *testing.T) {
		// symlink-inside -> internal/sub
		// symlink-inside/../parent.yaml should resolve to internal/parent.yaml
		// (not base/parent.yaml as lexical clean would do)
		resolved, err := ResolveContainedPath(base, "symlink-inside/../parent.yaml")
		require.NoError(t, err)
		canonParent, err := filepath.EvalSymlinks(parentFile)
		require.NoError(t, err)
		assert.Equal(t, canonParent, resolved)
	})

	// 3. Dangling symlink
	danglingSymlink := filepath.Join(base, "dangling")
	require.NoError(t, os.Symlink(filepath.Join(base, "ghost"), danglingSymlink))

	t.Run("dangling symlink is rejected", func(t *testing.T) {
		_, err := ResolveContainedPath(base, "dangling")
		require.Error(t, err)
	})

	t.Run("dangling symlink intermediate path is rejected", func(t *testing.T) {
		_, err := ResolveContainedPath(base, "dangling/subfile.yaml")
		require.Error(t, err)
	})

	// 4. Symlink loop
	loopA := filepath.Join(base, "loopA")
	loopB := filepath.Join(base, "loopB")
	require.NoError(t, os.Symlink(loopB, loopA))
	require.NoError(t, os.Symlink(loopA, loopB))

	t.Run("symlink loop is rejected", func(t *testing.T) {
		_, err := ResolveContainedPath(base, "loopA")
		require.Error(t, err)
	})

	// 5. Workspace root resolution with symlinks and parent traversal
	t.Run("absolute workspace root preserves symlink parent traversal", func(t *testing.T) {
		rootFolder := t.TempDir()
		actualFolder := t.TempDir()
		actualChild := filepath.Join(actualFolder, "child")
		require.NoError(t, os.Mkdir(actualChild, 0o750))
		targetFile := filepath.Join(actualChild, "target.yaml")
		require.NoError(t, os.WriteFile(targetFile, []byte("target"), 0o600))

		link := filepath.Join(rootFolder, "link")
		require.NoError(t, os.Symlink(actualChild, link))

		configuredBase := link + string(filepath.Separator) + ".."
		resolved, err := ResolveContainedPath(configuredBase, "child/target.yaml")
		require.NoError(t, err)

		canonTarget, err := filepath.EvalSymlinks(targetFile)
		require.NoError(t, err)
		assert.Equal(t, canonTarget, resolved)

		// A file outside /tmp/actual (even inside /tmp/root) must be rejected
		outsideInRoot := filepath.Join(rootFolder, "root-file.yaml")
		require.NoError(t, os.WriteFile(outsideInRoot, []byte("root file"), 0o600))
		_, err = ResolveContainedPath(configuredBase, outsideInRoot)
		require.Error(t, err)
		assert.True(t, errors.Is(err, ErrPathEscapesWorkspace))
	})

	t.Run("relative workspace root preserves symlink parent traversal", func(t *testing.T) {
		rootFolder := t.TempDir()
		actualFolder := t.TempDir()
		actualChild := filepath.Join(actualFolder, "child")
		require.NoError(t, os.Mkdir(actualChild, 0o750))
		targetFile := filepath.Join(actualChild, "target.yaml")
		require.NoError(t, os.WriteFile(targetFile, []byte("target"), 0o600))

		link := filepath.Join(rootFolder, "link")
		require.NoError(t, os.Symlink(actualChild, link))

		origWd, err := os.Getwd()
		require.NoError(t, err)
		require.NoError(t, os.Chdir(rootFolder))
		defer func() {
			_ = os.Chdir(origWd)
		}()

		configuredBase := "link" + string(filepath.Separator) + ".."
		resolved, err := ResolveContainedPath(configuredBase, "child/target.yaml")
		require.NoError(t, err)

		canonTarget, err := filepath.EvalSymlinks(targetFile)
		require.NoError(t, err)
		assert.Equal(t, canonTarget, resolved)
	})
}

func TestResolveContainedPath_BackslashInFilenameUnix(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("backslash in filename is only valid on non-Windows platforms")
	}
	base := t.TempDir()

	// Create directory "a" with file "b" inside
	subDir := filepath.Join(base, "a")
	require.NoError(t, os.Mkdir(subDir, 0o750))
	nestedFile := filepath.Join(subDir, "b")
	require.NoError(t, os.WriteFile(nestedFile, []byte("nested content"), 0o600))

	// Create file "a\b" in base
	backslashFile := filepath.Join(base, "a\\b")
	require.NoError(t, os.WriteFile(backslashFile, []byte("backslash content"), 0o600))

	// Resolving "a\b" must resolve to backslashFile, not nestedFile
	resolved, err := ResolveContainedPath(base, "a\\b")
	require.NoError(t, err)
	canonBackslash, err := filepath.EvalSymlinks(backslashFile)
	require.NoError(t, err)
	assert.Equal(t, canonBackslash, resolved)

	content, err := os.ReadFile(resolved)
	require.NoError(t, err)
	assert.Equal(t, "backslash content", string(content))
}

func TestIsPathContained_TableDriven(t *testing.T) {
	base := t.TempDir()
	validFile := filepath.Join(base, "valid.yaml")
	require.NoError(t, os.WriteFile(validFile, []byte("content"), 0o600))

	outside := t.TempDir()
	outsideFile := filepath.Join(outside, "outside.yaml")
	require.NoError(t, os.WriteFile(outsideFile, []byte("content"), 0o600))

	assert.True(t, IsPathContained(base, validFile))
	assert.True(t, IsPathContained(base, base))
	assert.False(t, IsPathContained(base, outsideFile))
	assert.False(t, IsPathContained(base, filepath.Join(base, "does-not-exist.yaml")))
}
