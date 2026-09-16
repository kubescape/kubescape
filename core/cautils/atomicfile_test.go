package cautils

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func atomicTempFiles(t *testing.T, destination string) []string {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(
		filepath.Dir(destination),
		"."+filepath.Base(destination)+".tmp-*",
	))
	require.NoError(t, err)
	return matches
}

func TestWriteFileAtomically_CreatesNewFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "report.json")
	content := []byte("{\"cluster\":\"prod\"}")

	require.NoError(t, WriteFileAtomically(path, content, 0o600))

	got, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, content, got)
	assert.Empty(t, atomicTempFiles(t, path))
}

func TestWriteFileAtomically_CreatesNestedDirectories(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "one", "two", "three", "report.json")

	require.NoError(t, WriteFileAtomically(path, []byte("complete"), 0o600))

	got, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, "complete", string(got))
	info, err := os.Stat(filepath.Dir(path))
	require.NoError(t, err)
	assert.True(t, info.IsDir())
}

func TestWriteFileAtomically_ReplacesExistingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "report.json")
	require.NoError(t, os.WriteFile(path, []byte("old report"), 0o600))

	require.NoError(t, WriteFileAtomically(path, []byte("new report"), 0o600))

	got, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, "new report", string(got))
	assert.Empty(t, atomicTempFiles(t, path))
}

func TestWriteFileAtomically_AppliesRequestedPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not expose Unix permission bits")
	}

	tests := []struct {
		name string
		perm os.FileMode
	}{
		{name: "owner only", perm: 0o600},
		{name: "owner executable", perm: 0o700},
		{name: "group readable", perm: 0o640},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "artifact")
			require.NoError(t, WriteFileAtomically(path, []byte("payload"), tt.perm))

			info, err := os.Stat(path)
			require.NoError(t, err)
			assert.Equal(t, tt.perm, info.Mode().Perm())
		})
	}
}

func TestWriteFileAtomically_ReplacementUsesNewPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not expose Unix permission bits")
	}

	path := filepath.Join(t.TempDir(), "report")
	require.NoError(t, os.WriteFile(path, []byte("old"), 0o644))

	require.NoError(t, WriteFileAtomically(path, []byte("new"), 0o600))

	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
}

func TestWriteFileAtomically_EmptyPayloadIsACompleteFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "empty")
	require.NoError(t, os.WriteFile(path, []byte("old"), 0o600))

	require.NoError(t, WriteFileAtomically(path, nil, 0o600))

	got, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Empty(t, got)
	assert.Empty(t, atomicTempFiles(t, path))
}

func TestWriteFileAtomically_DoesNotFollowDestinationSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation is not generally available to unprivileged Windows tests")
	}

	dir := t.TempDir()
	victim := filepath.Join(dir, "victim.json")
	destination := filepath.Join(dir, "fleet.json")
	require.NoError(t, os.WriteFile(victim, []byte("do not overwrite"), 0o600))
	require.NoError(t, os.Symlink(victim, destination))

	require.NoError(t, WriteFileAtomically(destination, []byte("fleet report"), 0o600))

	victimData, err := os.ReadFile(victim)
	require.NoError(t, err)
	assert.Equal(t, "do not overwrite", string(victimData))

	destinationData, err := os.ReadFile(destination)
	require.NoError(t, err)
	assert.Equal(t, "fleet report", string(destinationData))
	info, err := os.Lstat(destination)
	require.NoError(t, err)
	assert.Zero(t, info.Mode()&os.ModeSymlink)
}

func TestWriteFileAtomically_PreservesDestinationWhenDirectoryCreationFails(t *testing.T) {
	root := t.TempDir()
	blocker := filepath.Join(root, "not-a-directory")
	require.NoError(t, os.WriteFile(blocker, []byte("blocker"), 0o600))
	path := filepath.Join(blocker, "report.json")

	err := WriteFileAtomically(path, []byte("new"), 0o600)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "create output directory")
	got, readErr := os.ReadFile(blocker)
	require.NoError(t, readErr)
	assert.Equal(t, "blocker", string(got))
}

func TestWriteFileAtomically_PreservesDestinationWhenRenameFails(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("directory replacement errors differ on Windows")
	}

	dir := t.TempDir()
	destination := filepath.Join(dir, "report.json")
	require.NoError(t, os.Mkdir(destination, 0o750))
	marker := filepath.Join(destination, "keep")
	require.NoError(t, os.WriteFile(marker, []byte("existing"), 0o600))

	err := WriteFileAtomically(destination, []byte("new report"), 0o600)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "replace output")
	got, readErr := os.ReadFile(marker)
	require.NoError(t, readErr)
	assert.Equal(t, "existing", string(got))
	assert.Empty(t, atomicTempFiles(t, destination))
}

func TestWriteFileAtomically_CleansTemporaryFileWhenRenameFailsRepeatedly(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("directory replacement errors differ on Windows")
	}

	dir := t.TempDir()
	destination := filepath.Join(dir, "report")
	require.NoError(t, os.Mkdir(destination, 0o750))
	require.NoError(t, os.WriteFile(filepath.Join(destination, "keep"), []byte("x"), 0o600))

	for i := 0; i < 20; i++ {
		err := WriteFileAtomically(destination, []byte(fmt.Sprintf("attempt-%d", i)), 0o600)
		require.Error(t, err)
		assert.Empty(t, atomicTempFiles(t, destination))
	}
}

func TestWriteFileAtomically_ConcurrentReadersNeverSeePartialContent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "report.json")
	oldContent := bytes.Repeat([]byte("a"), 512*1024)
	newContent := bytes.Repeat([]byte("b"), 512*1024)
	require.NoError(t, os.WriteFile(path, oldContent, 0o600))

	stop := make(chan struct{})
	errs := make(chan error, 1)
	var readers sync.WaitGroup
	for i := 0; i < 8; i++ {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				got, err := os.ReadFile(path)
				if err != nil {
					select {
					case errs <- err:
					default:
					}
					return
				}
				if !bytes.Equal(got, oldContent) && !bytes.Equal(got, newContent) {
					select {
					case errs <- fmt.Errorf("reader observed %d bytes of mixed or partial content", len(got)):
					default:
					}
					return
				}
			}
		}()
	}

	for i := 0; i < 20; i++ {
		content := oldContent
		if i%2 == 0 {
			content = newContent
		}
		require.NoError(t, WriteFileAtomically(path, content, 0o600))
	}
	close(stop)
	readers.Wait()

	select {
	case err := <-errs:
		require.NoError(t, err)
	default:
	}
	assert.Empty(t, atomicTempFiles(t, path))
}

func TestWriteFileAtomically_LongBaseNameStillUsesDestinationDirectory(t *testing.T) {
	dir := t.TempDir()
	name := strings.Repeat("r", 80) + ".json"
	path := filepath.Join(dir, name)

	require.NoError(t, WriteFileAtomically(path, []byte("report"), 0o600))

	got, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, "report", string(got))
	assert.Empty(t, atomicTempFiles(t, path))
}

func TestWriteFileAtomically_SequentialReplacementsRemainReadable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "report")

	for i := 0; i < 50; i++ {
		want := []byte(fmt.Sprintf("generation-%03d-%s", i, strings.Repeat("x", i)))
		require.NoError(t, WriteFileAtomically(path, want, 0o600))
		got, err := os.ReadFile(path)
		require.NoError(t, err)
		assert.Equal(t, want, got)
	}
	assert.Empty(t, atomicTempFiles(t, path))
}

func TestWriteFileAtomically_ErrorWrapsUnderlyingFilesystemFailure(t *testing.T) {
	root := t.TempDir()
	blocker := filepath.Join(root, "blocker")
	require.NoError(t, os.WriteFile(blocker, []byte("x"), 0o600))

	err := WriteFileAtomically(filepath.Join(blocker, "report"), []byte("data"), 0o600)

	require.Error(t, err)
	assert.True(t, errors.Is(err, os.ErrExist) || errors.Is(err, os.ErrNotExist) || strings.Contains(err.Error(), "not a directory"))
	assert.Contains(t, err.Error(), "report")
}

func TestWriteFileAtomically_ExistingOpenReaderKeepsConsistentGeneration(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not permit replacement while a file is open")
	}

	path := filepath.Join(t.TempDir(), "report")
	require.NoError(t, os.WriteFile(path, []byte("old generation"), 0o600))
	reader, err := os.Open(path)
	require.NoError(t, err)
	defer reader.Close()

	require.NoError(t, WriteFileAtomically(path, []byte("new generation"), 0o600))

	newView, err := os.ReadFile(reader.Name())
	require.NoError(t, err)
	assert.Equal(t, "new generation", string(newView))

	openedView := make([]byte, len("old generation"))
	_, err = reader.Read(openedView)
	require.NoError(t, err)
	assert.Equal(t, "old generation", string(openedView))
}

func TestWriteFileAtomically_CompletesWithinReasonableTime(t *testing.T) {
	path := filepath.Join(t.TempDir(), "report")
	started := time.Now()
	require.NoError(t, WriteFileAtomically(path, bytes.Repeat([]byte("x"), 1024), 0o600))
	assert.Less(t, time.Since(started), 5*time.Second)
}

func TestWriteFileAtomically_ConcurrentWritersCommitWholeGenerations(t *testing.T) {
	path := filepath.Join(t.TempDir(), "shared-report")
	const writers = 24
	payloads := make([][]byte, writers)
	for i := range payloads {
		payloads[i] = []byte(fmt.Sprintf("writer-%02d:%s", i, strings.Repeat(string(rune('a'+i%26)), 32*1024)))
	}

	start := make(chan struct{})
	errs := make(chan error, writers)
	var wg sync.WaitGroup
	for i := range payloads {
		wg.Add(1)
		go func(payload []byte) {
			defer wg.Done()
			<-start
			errs <- WriteFileAtomically(path, payload, 0o600)
		}(payloads[i])
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}

	got, err := os.ReadFile(path)
	require.NoError(t, err)
	matches := 0
	for _, payload := range payloads {
		if bytes.Equal(got, payload) {
			matches++
		}
	}
	assert.Equal(t, 1, matches, "the destination must contain one complete writer generation")
	assert.Empty(t, atomicTempFiles(t, path))
}

func TestWriteFileAtomically_HiddenAndUnicodeDestinations(t *testing.T) {
	for _, name := range []string{".fleet-report", "集群报告.json", "report with spaces.json"} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), name)
			require.NoError(t, WriteFileAtomically(path, []byte(name), 0o600))
			got, err := os.ReadFile(path)
			require.NoError(t, err)
			assert.Equal(t, name, string(got))
			assert.Empty(t, atomicTempFiles(t, path))
		})
	}
}
